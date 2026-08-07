[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [ValidateRange(60, 900)][int]$TimeoutSeconds = 300,
    [ValidateRange(0, 65535)][int]$WebPort = 0,
    [ValidateRange(0, 65535)][int]$TcpPort = 0,
    [ValidateRange(0, 65535)][int]$UdpPort = 0,
    [AllowEmptyString()][string]$ScratchRoot = '',
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$ExpectedCommit
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
$w12CollectorUserSid = (New-Object Security.Principal.NTAccount(
    $env:COMPUTERNAME, 'CodexSandboxOffline'
)).Translate([Security.Principal.SecurityIdentifier]).Value
$w12CollectorGroupSid = (New-Object Security.Principal.NTAccount(
    $env:COMPUTERNAME, 'CodexSandboxUsers'
)).Translate([Security.Principal.SecurityIdentifier]).Value
$w12CollectorSids = @()
$activationSchema = 'ese.v92.w12.activation/v2'
$runtimeSchema = 'ese.v92.w12.security-runtime/v2'
$challengeSchema = 'ese.v92.w12.browser-challenge/v2'
$handoffSchema = 'ese.v92.w12.browser-handoff/v3'
$readySchema = 'ese.v92.w12.browser-ready/v3'
$doneSchema = 'ese.v92.w12.browser-done/v3'
$browserTraceSchema = 'ese.v92.w12.browser-cdp/v3'
$caseOrder = @(
    'W12-RUNTIME-READY',
    'W12-RUNTIME-LOGIN',
    'W12-RUNTIME-BROADCAST',
    'W12-RUNTIME-PLAYER-CAPABILITY',
    'W12-RUNTIME-PLAYLIST',
    'W12-RUNTIME-RANGE',
    'W12-RUNTIME-FORGED-CAPABILITY',
    'W12-RUNTIME-LOG-CANARY',
    'W12-RUNTIME-LOGOUT-REVOCATION',
    'W12-RUNTIME-STOP-REVOCATION',
    'W12-RUNTIME-ROLLOVER-REVOCATION',
    'W12-RUNTIME-RESTART-REVOCATION',
    'W12-RUNTIME-TERMINATION',
    'W12-RUNTIME-ARTIFACT-SCAN'
)
$caseResults = [ordered]@{}
$sensitiveResponses = New-Object 'Collections.Generic.List[object]'
$sensitiveValues = New-Object 'Collections.Generic.List[string]'
$process = $null
$httpClient = $null
$httpHandler = $null
$ports = $null
$canary = ''
$failureStage = 'W12-RUNTIME-READY'
$flowSucceeded = $false
$terminationConfirmed = $true
$scratchRemoved = $false
$canarySha256 = ('0' * 64)
$canaryLogHits = -1
$canaryArtifactHits = -1
$forgedBodyHits = -1
$secretsPersisted = $true
$sensitiveUrlsPersisted = $true
$startedAt = [DateTime]::UtcNow
$launchIndex = 0
$candidate = [ordered]@{
    build_commit = ''
    emule_sha256 = ''
    build_info_sha256 = ''
    release = ''
}
$activation = $null
$binding = $null
$runId = ''
$challengeNonce = ''
$browserHandshakeComplete = $false
$evidenceVerifier = $null
function Assert-W12 {
    param([bool]$Condition)
    if (-not $Condition) { throw 'W12 runtime assertion failed' }
}
function Set-W12Case {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'FAIL')][string]$Status,
        [AllowNull()][Nullable[int]]$HttpStatus,
        [Parameter(Mandatory = $true)][string[]]$Checks
    )
    if ($caseOrder -notcontains $Id -or $caseResults.Contains($Id) -or $Checks.Count -eq 0) {
        throw 'W12 runtime case bookkeeping failed'
    }
    $caseResults[$Id] = [ordered]@{
        id = $Id
        status = $Status
        http_status = if ($null -eq $HttpStatus) { $null } else { [int]$HttpStatus }
        checks = @($Checks)
    }
}
function Get-Sha256File {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Get-Sha256Text {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}
function Get-GitBlobSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Commit,
        [Parameter(Mandatory = $true)][string]$RepositoryPath,
        [Parameter(Mandatory = $true)][string]$TemporaryRoot
    )
    Assert-W12 ($RepositoryPath -notmatch '[\\:]' -and $RepositoryPath -notmatch '^\.\.')
    $blob = (& git -C $Repository rev-parse ("{0}:{1}" -f $Commit, $RepositoryPath)).Trim().ToLowerInvariant()
    Assert-W12 ($blob -match '^[0-9a-f]{40}$')
    $target = Join-Path $TemporaryRoot ("git-blob-{0}.tmp" -f $blob)
    $process = Start-Process -FilePath git -ArgumentList @('-C', $Repository, 'cat-file', 'blob', $blob) `
        -RedirectStandardOutput $target -RedirectStandardError (Join-Path $TemporaryRoot 'git-blob.stderr.tmp') -WindowStyle Hidden -PassThru
    Assert-W12 ($process.Handle -ne [IntPtr]::Zero)
    $finished = $process.WaitForExit(15000)
    if ($finished) { $process.WaitForExit() }
    Assert-W12 ($finished -and $process.ExitCode -eq 0 -and
        (Test-Path -LiteralPath $target -PathType Leaf) -and
        (Get-Item -LiteralPath $target).Length -gt 0)
    try { return Get-Sha256File -Path $target } finally { Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue }
}
function Export-W12GitBlob {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Commit,
        [Parameter(Mandatory = $true)][string]$RepositoryPath,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$PrivateScratch,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    Assert-W12ScratchWrite -Scratch $PrivateScratch -Path $Destination
    Assert-W12 ($RepositoryPath -notmatch '[\\:]' -and $RepositoryPath -notmatch '^\.\.')
    Assert-W12 (-not (Test-Path -LiteralPath $Destination))
    $blob = (& git -C $Repository rev-parse ("{0}:{1}" -f $Commit, $RepositoryPath)).Trim().ToLowerInvariant()
    Assert-W12 ($blob -match '^[0-9a-f]{40}$')
    $stderr = Join-Path $PrivateScratch 'git-blob-export.stderr.tmp'
    Assert-W12ScratchWrite -Scratch $PrivateScratch -Path $stderr
    $process = Start-Process -FilePath git -ArgumentList @('-C', $Repository, 'cat-file', 'blob', $blob) `
        -RedirectStandardOutput $Destination -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    Assert-W12 ($process.Handle -ne [IntPtr]::Zero)
    $finished = $process.WaitForExit(15000)
    if ($finished) { $process.WaitForExit() }
    Assert-W12 ($finished -and $process.ExitCode -eq 0 -and
        (Test-Path -LiteralPath $Destination -PathType Leaf) -and
        (Get-Item -LiteralPath $Destination).Length -gt 0)
    Assert-W12 ((Get-Sha256File -Path $Destination) -ceq $ExpectedSha256)
}
function New-W12Activation {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Commit,
        [Parameter(Mandatory = $true)][string]$TemporaryRoot
    )
    $resolved = (& git -C $Repository rev-parse ("{0}^{{commit}}" -f $Commit)).Trim().ToLowerInvariant()
    Assert-W12 ($resolved -ceq $Commit.ToLowerInvariant())
    $tree = @(& git -C $Repository ls-tree -r --full-tree $resolved -- srchybrid)
    Assert-W12 ($tree.Count -gt 0)
    $entries = New-Object 'Collections.Generic.List[object]'
    foreach ($line in $tree) {
        if ($line -notmatch '^[0-9]{6}\s+blob\s+(?<blob>[0-9a-f]{40})\t(?<path>srchybrid/.+)$') { throw 'W12 production tree is not blob-only' }
        $null = $entries.Add([pscustomobject]@{ blob = $Matches['blob']; path = $Matches['path'] })
    }
    # Canonical bytes: UTF-8(blob_oid + real TAB + path + real LF), sorted by Git path.
    $canonical = New-Object 'Collections.Generic.List[string]'
    $previousPath = $null
    foreach ($entry in $entries) {
        if ($null -ne $previousPath) {
            Assert-W12 ([StringComparer]::Ordinal.Compare([string]$previousPath, [string]$entry.path) -lt 0)
        }
        $null = $canonical.Add(("{0}`t{1}`n" -f $entry.blob, $entry.path))
        $previousPath = $entry.path
    }
    $toolHashes = [ordered]@{}
    $toolPaths = [ordered]@{
        runner = 'tools/architecture/run_w12_security_runtime.ps1'
        verifier = 'tools/architecture/verify_w12_security_evidence.py'
        collector = 'tools/architecture/collect_w12_browser_cdp.mjs'
        test = 'tests/test_v92_m2a_w12_security_evidence.py'
        ratchet = 'tools/architecture/verify_m2a00_migration_ratchet.py'
    }
    foreach ($toolName in @('runner', 'verifier', 'collector', 'test', 'ratchet')) {
        $toolHashes[$toolName] = Get-GitBlobSha256 -Repository $Repository -Commit $resolved `
            -RepositoryPath $toolPaths[$toolName] -TemporaryRoot $TemporaryRoot
    }
    return [ordered]@{
        schema = $activationSchema
        activation_commit = $resolved
        production_tree_sha256 = Get-Sha256Text -Value ([string]::Join('', @($canonical)))
        production_path_count = $canonical.Count
        tool_sha256 = $toolHashes
    }
}
function Get-RandomHex {
    param([ValidateRange(1, 128)][int]$ByteCount)
    $bytes = New-Object byte[] $ByteCount
    $algorithm = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $algorithm.GetBytes($bytes) } finally { $algorithm.Dispose() }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}
function Get-Md5UnicodeText {
    param([Parameter(Mandatory = $true)][string]$Value)
    $algorithm = [Security.Cryptography.MD5]::Create()
    try {
        return ([BitConverter]::ToString(
            $algorithm.ComputeHash([Text.Encoding]::Unicode.GetBytes($Value))
        )).Replace('-', '')
    } finally {
        $algorithm.Dispose()
    }
}
function Set-W12IniValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][string]$PrivateScratch
    )
    Assert-W12ScratchWrite -Scratch $PrivateScratch -Path $Path
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $parent
    }
    $lines = New-Object 'Collections.Generic.List[string]'
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        foreach ($line in [IO.File]::ReadAllLines($Path)) { $null = $lines.Add($line) }
    }
    $sectionPattern = '(?i)^\s*\[' + [regex]::Escape($Section) + '\]\s*$'
    $keyPattern = '(?i)^\s*' + [regex]::Escape($Key) + '\s*='
    $sectionIndex = -1
    $sectionEnd = $lines.Count
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -match $sectionPattern) {
            $sectionIndex = $index
            for ($next = $index + 1; $next -lt $lines.Count; $next++) {
                if ($lines[$next] -match '^\s*\[.+\]\s*$') { $sectionEnd = $next; break }
            }
            break
        }
    }
    $replacement = '{0}={1}' -f $Key, $Value
    if ($sectionIndex -ge 0) {
        for ($index = $sectionIndex + 1; $index -lt $sectionEnd; $index++) {
            if ($lines[$index] -match $keyPattern) {
                $lines[$index] = $replacement
                [IO.File]::WriteAllLines($Path, $lines, [Text.UTF8Encoding]::new($false))
                return
            }
        }
        $lines.Insert($sectionEnd, $replacement)
    } else {
        if ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -ne '') { $null = $lines.Add('') }
        $null = $lines.Add(('[' + $Section + ']'))
        $null = $lines.Add($replacement)
    }
    [IO.File]::WriteAllLines($Path, $lines, [Text.UTF8Encoding]::new($false))
}
function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}
function Get-FreeUdpPort {
    $socket = [Net.Sockets.UdpClient]::new(0, [Net.Sockets.AddressFamily]::InterNetwork)
    try { return ([Net.IPEndPoint]$socket.Client.LocalEndPoint).Port } finally { $socket.Dispose() }
}
function Resolve-W12Ports {
    param([int]$RequestedWeb, [int]$RequestedTcp, [int]$RequestedUdp)
    for ($attempt = 0; $attempt -lt 32; $attempt++) {
        $web = if ($RequestedWeb -eq 0) { Get-FreeTcpPort } else { $RequestedWeb }
        $tcp = if ($RequestedTcp -eq 0) { Get-FreeTcpPort } else { $RequestedTcp }
        $udp = if ($RequestedUdp -eq 0) { Get-FreeUdpPort } else { $RequestedUdp }
        $unique = @(@($web, $tcp, $udp) | Sort-Object -Unique)
        if ($web -ge 1024 -and $tcp -ge 1024 -and $udp -ge 1024 -and
            $unique.Count -eq 3) {
            return [pscustomobject]@{ web = $web; tcp = $tcp; udp = $udp }
        }
    }
    throw 'Unable to allocate three distinct unprivileged ports'
}
function Get-BuildInfo {
    param([Parameter(Mandatory = $true)][string]$Path)
    $values = @{}
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ($line -match '^\s*([^:]+):\s*(.*?)\s*$') {
            $values[$Matches[1].Trim().ToLowerInvariant()] = $Matches[2].Trim()
        }
    }
    $commit = [string]$values['commit']
    $release = [string]$values['release']
    $dirty = [string]$values['dirty']
    Assert-W12 ($commit -match '^[0-9a-fA-F]{40}$')
    Assert-W12 (-not [string]::IsNullOrWhiteSpace($release))
    Assert-W12 ($dirty -eq 'false')
    return [pscustomobject]@{
        commit = $commit.ToLowerInvariant()
        release = $release
    }
}
function Get-HeaderValue {
    param([Parameter(Mandatory = $true)][object]$Response, [Parameter(Mandatory = $true)][string]$Name)
    $key = $Name.ToLowerInvariant()
    if ($Response.headers.ContainsKey($key)) { return [string]$Response.headers[$key] }
    return ''
}
function Invoke-W12Http {
    param(
        [Parameter(Mandatory = $true)][object]$Client,
        [Parameter(Mandatory = $true)][Uri]$BaseUri,
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowEmptyString()][string]$Csrf = '',
        [AllowEmptyString()][string]$Range = ''
    )
    Assert-W12 ($Path.StartsWith('/') -and $Path.IndexOfAny([char[]]@("`r", "`n")) -lt 0)
    $uri = [Uri]::new($BaseUri, $Path)
    Assert-W12 ($uri.Scheme -eq 'http' -and $uri.Host -eq '127.0.0.1' -and $uri.Port -eq $BaseUri.Port)
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $uri)
    try {
        if ($Csrf) {
            $null = $request.Headers.TryAddWithoutValidation('X-CSRF-Token', $Csrf)
            $null = $request.Headers.TryAddWithoutValidation('Sec-Fetch-Site', 'same-origin')
            $null = $request.Headers.TryAddWithoutValidation('Origin', $BaseUri.GetLeftPart([UriPartial]::Authority))
        }
        if ($Range) { $null = $request.Headers.TryAddWithoutValidation('Range', $Range) }
        $response = $Client.SendAsync($request).GetAwaiter().GetResult()
        try {
            $bytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            $headers = @{}
            foreach ($header in $response.Headers) {
                $headers[$header.Key.ToLowerInvariant()] = [string]::Join(', ', @($header.Value))
            }
            foreach ($header in $response.Content.Headers) {
                $headers[$header.Key.ToLowerInvariant()] = [string]::Join(', ', @($header.Value))
            }
            return [pscustomobject]@{
                status = [int]$response.StatusCode
                headers = $headers
                bytes = [byte[]]$bytes
                text = [Text.Encoding]::UTF8.GetString($bytes)
            }
        } finally {
            $response.Dispose()
        }
    } finally {
        $request.Dispose()
    }
}
function Add-SensitiveResponse {
    param([Parameter(Mandatory = $true)][object]$Response)
    $null = $sensitiveResponses.Add($Response)
}
function Test-HardenedResponse {
    param([Parameter(Mandatory = $true)][object]$Response)
    $cache = Get-HeaderValue -Response $Response -Name 'Cache-Control'
    $referrer = Get-HeaderValue -Response $Response -Name 'Referrer-Policy'
    return $cache -match '(?i)(?:^|,)\s*no-store\s*(?:,|$)' -and
        $referrer.Trim().ToLowerInvariant() -eq 'no-referrer'
}
function Start-W12Node {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$NodeRoot,
        [Parameter(Mandatory = $true)][string]$TemporaryRoot,
        [Parameter(Mandatory = $true)][string]$PrivateScratch,
        [Parameter(Mandatory = $true)][object]$Ports
    )
    $script:launchIndex++
    $stdout = Join-Path $NodeRoot ("w12-runtime-{0}.stdout.tmp" -f $script:launchIndex)
    $stderr = Join-Path $NodeRoot ("w12-runtime-{0}.stderr.tmp" -f $script:launchIndex)
    Assert-W12ScratchWrite -Scratch $PrivateScratch -Path $stdout
    Assert-W12ScratchWrite -Scratch $PrivateScratch -Path $stderr
    $isolatedEnvironment = @('TEMP', 'TMP', 'APPDATA', 'LOCALAPPDATA', 'USERPROFILE')
    $oldEnvironment = @{}
    foreach ($name in $isolatedEnvironment) { $oldEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    try {
        foreach ($name in $isolatedEnvironment) { [Environment]::SetEnvironmentVariable($name, $TemporaryRoot, 'Process') }
        return Start-Process -FilePath $Executable -ArgumentList @(
            '--portable', '--ignoreinstances', '--headless',
            "--metrics-port=$($Ports.web)", "--tcp-port=$($Ports.tcp)",
            "--udp-port=$($Ports.udp)"
        ) -WorkingDirectory $NodeRoot -WindowStyle Hidden -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr -PassThru
    } finally {
        foreach ($name in $isolatedEnvironment) { [Environment]::SetEnvironmentVariable($name, $oldEnvironment[$name], 'Process') }
    }
}
function Stop-W12ProcessTree {
    param([AllowNull()][Diagnostics.Process]$Target, [Parameter(Mandatory = $true)][string]$NodeRoot)
    if ($null -ne $Target) {
        try { $Target.Refresh() } catch { }
        if (-not $Target.HasExited) {
            $taskkill = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\taskkill.exe') `
                -ArgumentList '/PID', ([string]$Target.Id), '/T', '/F' -WindowStyle Hidden -PassThru
            $finished = $taskkill.WaitForExit(15000)
            if (-not $finished) { try { $taskkill.Kill() } catch { } }
            $null = $Target.WaitForExit(15000)
        }
        try { $Target.Dispose() } catch { }
    }
    Start-Sleep -Milliseconds 250
    $prefix = [IO.Path]::GetFullPath($NodeRoot).TrimEnd('\') + '\'
    $owned = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        try { $_.Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) } catch { $false }
    })
    foreach ($item in $owned) {
        try { Stop-Process -Id $item.Id -Force -ErrorAction Stop } catch { }
    }
    if ($owned.Count -gt 0) { Start-Sleep -Milliseconds 500 }
    return @(
        Get-Process -ErrorAction SilentlyContinue | Where-Object {
            try { $_.Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) } catch { $false }
        }
    ).Count -eq 0
}
function Wait-W12Ready {
    param(
        [Parameter(Mandatory = $true)][object]$Client,
        [Parameter(Mandatory = $true)][Uri]$BaseUri,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Target,
        [Parameter(Mandatory = $true)][int]$Seconds
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $Target.Refresh()
        if ($Target.HasExited) { throw 'W12 node exited before readiness' }
        try {
            $response = Invoke-W12Http -Client $Client -BaseUri $BaseUri -Path '/api/status'
            if ($response.status -eq 200) { return $response }
        } catch { }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'W12 node readiness timeout'
}
function Assert-LoopbackListener {
    param([Parameter(Mandatory = $true)][int]$Port, [Parameter(Mandatory = $true)][int]$ProcessId)
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop | Where-Object {
        $_.OwningProcess -eq $ProcessId
    })
    Assert-W12 ($listeners.Count -gt 0)
    foreach ($listener in $listeners) {
        Assert-W12 ($listener.LocalAddress -eq '127.0.0.1' -or $listener.LocalAddress -eq '::1')
    }
}
function Get-CapabilityPath {
    param([Parameter(Mandatory = $true)][string]$Html, [Parameter(Mandatory = $true)][string]$StreamKey)
    $pattern = "(?<path>/h/[0-9a-f]{64}/[1-9][0-9]*/$StreamKey/stream\.m3u8)"
    $matches = [regex]::Matches($Html, $pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    Assert-W12 ($matches.Count -eq 1)
    return $matches[0].Groups['path'].Value
}
function Get-CapabilityToken {
    param([Parameter(Mandatory = $true)][string]$CapabilityPath)
    $match = [regex]::Match($CapabilityPath, '^/h/(?<token>[0-9a-f]{64})/')
    Assert-W12 $match.Success
    return $match.Groups['token'].Value
}
function Get-PlaylistLeaf {
    param([Parameter(Mandatory = $true)][string]$Playlist, [Parameter(Mandatory = $true)][string]$SuffixPattern)
    $found = @()
    foreach ($line in ($Playlist -split "`r?`n")) {
        $value = $line.Trim()
        if ($value -and -not $value.StartsWith('#') -and $value -match $SuffixPattern) {
            $found += $value
        }
    }
    Assert-W12 ($found.Count -gt 0)
    return [string]$found[0]
}
function New-CapabilityResourcePath {
    param([Parameter(Mandatory = $true)][string]$CapabilityPath, [Parameter(Mandatory = $true)][string]$Leaf)
    Assert-W12 ($Leaf -match '^(?:stream(?:_[0-4])?\.m3u8|seg_(?:[0-4]_)?[0-9]{5,10}\.ts)$')
    return $CapabilityPath.Substring(0, $CapabilityPath.LastIndexOf('/') + 1) + $Leaf
}
function Count-Bytes {
    param([Parameter(Mandatory = $true)][byte[]]$Haystack, [Parameter(Mandatory = $true)][byte[]]$Needle)
    if ($Needle.Length -eq 0 -or $Haystack.Length -lt $Needle.Length) { return 0 }
    $count = 0
    for ($index = 0; $index -le $Haystack.Length - $Needle.Length; $index++) {
        $same = $true
        for ($offset = 0; $offset -lt $Needle.Length; $offset++) {
            if ($Haystack[$index + $offset] -ne $Needle[$offset]) { $same = $false; break }
        }
        if ($same) { $count++; $index += $Needle.Length - 1 }
    }
    return $count
}
function Scan-W12Artifacts {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$Secrets,
        [Parameter(Mandatory = $true)][string]$Canary
    )
    $secretHits = 0
    $canaryHits = 0
    $urlHits = 0
    foreach ($file in @(Get-ChildItem -LiteralPath $Root -Recurse -Force -File -ErrorAction Stop)) {
        $bytes = [IO.File]::ReadAllBytes($file.FullName)
        foreach ($secret in $Secrets) {
            if ([string]::IsNullOrEmpty($secret)) { continue }
            $ascii = [Text.Encoding]::ASCII.GetBytes($secret)
            $unicode = [Text.Encoding]::Unicode.GetBytes($secret)
            $hits = (Count-Bytes -Haystack $bytes -Needle $ascii) +
                (Count-Bytes -Haystack $bytes -Needle $unicode)
            $secretHits += $hits
            if ($secret -ceq $Canary) { $canaryHits += $hits }
        }
        $asciiText = [Text.Encoding]::ASCII.GetString($bytes)
        $unicodeText = [Text.Encoding]::Unicode.GetString($bytes)
        $urlPattern = '(?i)(?:/h/[0-9a-f]{64}/[0-9]+/[0-9a-f]{32}/(?:stream(?:_[0-4])?\.m3u8|seg_(?:[0-4]_)?[0-9]{5,10}\.ts)|' +
            '[a-z]:\\+(?:users|documents and settings)\\+|(?<![0-9])(?!(?:127\.0\.0\.1)\b)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])|(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4})'
        $urlHits += [regex]::Matches($asciiText, $urlPattern).Count
        $urlHits += [regex]::Matches($unicodeText, $urlPattern).Count
    }
    return [pscustomobject]@{
        secret_hits = $secretHits
        canary_hits = $canaryHits
        sensitive_url_hits = $urlHits
    }
}
function Assert-W12PrivateScratch {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-W12 ($item.PSIsContainer -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0))
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentSid = $identity.User.Value
    $systemSid = 'S-1-5-18'
    $allowedSids = @($currentSid, $systemSid)
    $acl = Get-Acl -LiteralPath $item.FullName
    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    Assert-W12 ($acl.AreAccessRulesProtected -and $ownerSid -eq $currentSid)
    $rules = @($acl.Access | ForEach-Object {
        [pscustomobject]@{
            sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            type = $_.AccessControlType
            rights = $_.FileSystemRights
        }
    })
    Assert-W12 ($rules.Count -ge 1)
    Assert-W12 (@($rules | Where-Object {
        $_.type -ne [Security.AccessControl.AccessControlType]::Allow -or
        $_.sid -notin $allowedSids
    }).Count -eq 0)
    Assert-W12 (@($rules | Where-Object {
        $_.sid -eq $currentSid -and ($_.rights -band [Security.AccessControl.FileSystemRights]::FullControl)
    }).Count -ge 1)
}
function New-W12PrivateScratch {
    $root = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    Assert-W12 ($rootItem.PSIsContainer -and (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0))
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $path = Join-Path $root ('w12-runtime-' + [Guid]::NewGuid().ToString('N'))
    Assert-W12 (-not (Test-Path -LiteralPath $path))
    $null = New-Item -ItemType Directory -Path $path -ErrorAction Stop
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($identity.User)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity.User, 'FullControl', $inherit, 'None', $allow)))
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $inherit, 'None', $allow)))
    Set-Acl -LiteralPath $path -AclObject $acl
    Assert-W12PrivateScratch -Path $path
    return $path
}
function Assert-W12ExchangeScratch {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-W12 ($item.PSIsContainer -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0))
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowedSids = @($currentSid, 'S-1-5-18', $w12CollectorUserSid) + $w12CollectorSids
    $acl = Get-Acl -LiteralPath $item.FullName
    Assert-W12 ($acl.AreAccessRulesProtected -and
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $currentSid)
    $rules = @($acl.Access | ForEach-Object {
        [pscustomobject]@{
            sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            type = $_.AccessControlType
            rights = $_.FileSystemRights
        }
    })
    Assert-W12 (@($rules | Where-Object {
        $_.type -ne [Security.AccessControl.AccessControlType]::Allow -or $_.sid -notin $allowedSids
    }).Count -eq 0)
    foreach ($sid in $allowedSids) {
        Assert-W12 (@($rules | Where-Object { $_.sid -eq $sid }).Count -ge 1)
    }
}
function New-W12ExchangeScratch {
    param([Parameter(Mandatory = $true)][string]$Root)
    $root = [IO.Path]::GetFullPath($Root)
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    Assert-W12 ($rootItem.PSIsContainer -and (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0))
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentSid = $identity.User.Value
    $restrictedSids = @((Get-Acl -LiteralPath $root).Access | ForEach-Object {
        $sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if (-not $_.IsInherited -and
            $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Modify) -and
            $sid -match '^S-1-5-21-' -and
            $sid -notin @($currentSid, $w12CollectorUserSid, $w12CollectorGroupSid)) { $sid }
    } | Sort-Object -Unique)
    Assert-W12 ($restrictedSids.Count -eq 2)
    $script:w12CollectorSids = @($restrictedSids)
    $path = Join-Path $root ('w12-exchange-' + [Guid]::NewGuid().ToString('N'))
    Assert-W12 (-not (Test-Path -LiteralPath $path))
    $null = New-Item -ItemType Directory -Path $path -ErrorAction Stop
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($identity.User)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $allow = [Security.AccessControl.AccessControlType]::Allow
    foreach ($sid in @($currentSid, 'S-1-5-18')) {
        $principal = New-Object Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $principal, 'FullControl', $inherit, 'None', $allow)))
    }
    foreach ($collectorSid in @($w12CollectorUserSid) + $w12CollectorSids) {
        $collector = New-Object Security.Principal.SecurityIdentifier($collectorSid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $collector, 'Modify', $inherit, 'None', $allow)))
    }
    Set-Acl -LiteralPath $path -AclObject $acl
    Assert-W12ExchangeScratch -Path $path
    return $path
}
function Assert-W12ScratchWrite {
    param(
        [Parameter(Mandatory = $true)][string]$Scratch,
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateSet('Private', 'Exchange')][string]$Kind = 'Private'
    )
    if ($Kind -eq 'Private') { Assert-W12PrivateScratch -Path $Scratch }
    else { Assert-W12ExchangeScratch -Path $Scratch }
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = [IO.Path]::GetFullPath($Scratch).TrimEnd('\') + '\'
    Assert-W12 ($full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase))
    if (Test-Path -LiteralPath $full) {
        $item = Get-Item -LiteralPath $full -Force
        Assert-W12 (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
    }
}
function Write-W12Json {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowEmptyString()][string]$PrivateScratch = '',
        [ValidateSet('Private', 'Exchange')][string]$ScratchKind = 'Private'
    )
    if ($PrivateScratch) { Assert-W12ScratchWrite -Scratch $PrivateScratch -Path $Path -Kind $ScratchKind }
    if (Test-Path -LiteralPath $Path) { throw 'Refusing to overwrite W12 evidence' }
    $temporaryPath = $Path + '.writing'
    if (Test-Path -LiteralPath $temporaryPath) { throw 'Stale W12 atomic-write file exists' }
    $json = ($Value | ConvertTo-Json -Depth 10) -replace "`r`n", "`n" -replace "`r", "`n"
    try {
        [IO.File]::WriteAllText($temporaryPath, $json + "`n", [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporaryPath, $Path)
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue }
    }
}
function Get-W12JsonPropertyNames {
    param([Parameter(Mandatory = $true)][object]$Value)
    return @($Value.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
}
function Wait-W12BrowserEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Scratch,
        [Parameter(Mandatory = $true)][string]$RawPath,
        [Parameter(Mandatory = $true)][string]$DonePath,
        [Parameter(Mandatory = $true)][string]$ClaimPath,
        [Parameter(Mandatory = $true)][int]$Seconds
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        Assert-W12ExchangeScratch -Path $Scratch
        Assert-W12ScratchWrite -Scratch $Scratch -Path $DonePath -Kind Exchange
        Assert-W12ScratchWrite -Scratch $Scratch -Path $RawPath -Kind Exchange
        Assert-W12ScratchWrite -Scratch $Scratch -Path $ClaimPath -Kind Exchange
        if ((Test-Path -LiteralPath $ClaimPath -PathType Leaf) -and (Test-Path -LiteralPath $RawPath -PathType Leaf) -and (Test-Path -LiteralPath $DonePath -PathType Leaf)) {
            return
        }
        Start-Sleep -Milliseconds 200
    }
    throw 'W12 browser collector timed out waiting for its claimed raw/done evidence'
}
$package = (Resolve-Path -LiteralPath $PackagePath).Path
Assert-W12 (Test-Path -LiteralPath $package -PathType Container)
Assert-W12 (-not (Test-Path -LiteralPath (Join-Path $package '.git')))
$packageItem = Get-Item -LiteralPath $package -Force
Assert-W12 (($packageItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
$output = [IO.Path]::GetFullPath($OutputRoot)
Assert-W12 (-not (Test-Path -LiteralPath $output))
$packagePrefix = $package.TrimEnd('\') + '\'
Assert-W12 (-not $output.StartsWith($packagePrefix, [StringComparison]::OrdinalIgnoreCase))
$null = New-Item -ItemType Directory -Path $output
$scratch = $null
$exchange = $null
$scratchParentPrefix = $null
$exchangeParentPrefix = $null
try {
    Assert-W12 (-not [string]::IsNullOrWhiteSpace($ScratchRoot))
    $scratch = New-W12PrivateScratch
    $exchange = New-W12ExchangeScratch -Root $ScratchRoot
    $scratchParentPrefix = [IO.Path]::GetFullPath((Split-Path -Parent $scratch)).TrimEnd('\') + '\'
    $exchangeParentPrefix = [IO.Path]::GetFullPath((Split-Path -Parent $exchange)).TrimEnd('\') + '\'
    $outputPrefix = [IO.Path]::GetFullPath($output).TrimEnd('\') + '\'
    Assert-W12 (-not $scratch.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase))
    Assert-W12 (-not $scratch.StartsWith($packagePrefix, [StringComparison]::OrdinalIgnoreCase))
    Assert-W12 (-not $exchange.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase))
    Assert-W12 (-not $exchange.StartsWith($packagePrefix, [StringComparison]::OrdinalIgnoreCase))
    Assert-W12 (-not $exchange.StartsWith(($scratch.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase))
    $node = Join-Path $scratch 'node'
    $temporary = Join-Path $scratch 'temp'
    $null = Assert-W12PrivateScratch -Path $scratch
    $null = Assert-W12ExchangeScratch -Path $exchange
    $null = New-Item -ItemType Directory -Path $node
    $null = New-Item -ItemType Directory -Path $temporary
    $browserHandoff = Join-Path $exchange 'browser-handoff.json'
    $browserHandoffVerifier = Join-Path $scratch 'browser-handoff-verifier.json'
    $browserReady = Join-Path $exchange 'browser-ready.json'
    $browserClaim = Join-Path $exchange 'browser-collector.claim.json'
    $browserRawTrace = Join-Path $exchange 'browser-cdp-raw.json'
    $browserTrace = Join-Path $output 'browser-cdp-trace.json'
    $browserDone = Join-Path $exchange 'browser-done.json'
} catch {
    if ($null -ne $scratch -and (Test-Path -LiteralPath $scratch -PathType Container)) {
        try { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction Stop } catch { }
    }
    if ($null -ne $exchange -and (Test-Path -LiteralPath $exchange -PathType Container)) {
        try { Remove-Item -LiteralPath $exchange -Recurse -Force -ErrorAction Stop } catch { }
    }
    throw
}
# Global cleanup covers activation/package failures that occur before the runtime try/finally.
try {
$repository = (& git -C $PSScriptRoot rev-parse --show-toplevel).Trim()
Assert-W12 (-not [string]::IsNullOrWhiteSpace($repository))
$activation = New-W12Activation -Repository $repository -Commit $ExpectedCommit.ToLowerInvariant() -TemporaryRoot $temporary
$runId = Get-RandomHex -ByteCount 32
$challengeNonce = Get-RandomHex -ByteCount 32
$canary = Get-RandomHex -ByteCount 32
$canarySha256 = Get-Sha256Text -Value $canary
$binding = [ordered]@{
    activation_commit = $activation.activation_commit
    production_tree_sha256 = $activation.production_tree_sha256
    toolset_sha256 = Get-Sha256Text -Value ('{"collector":"' + $activation.tool_sha256.collector + '","ratchet":"' + $activation.tool_sha256.ratchet + '","runner":"' + $activation.tool_sha256.runner + '","test":"' + $activation.tool_sha256.test + '","verifier":"' + $activation.tool_sha256.verifier + '"}')
    run_id_sha256 = Get-Sha256Text -Value $runId
    challenge_nonce_sha256 = Get-Sha256Text -Value $challengeNonce
    canary_sha256 = $canarySha256
}
foreach ($transientSecret in @($runId, $challengeNonce, $canary)) {
    $null = $sensitiveValues.Add($transientSecret)
}
Write-W12Json -Value $activation -Path (Join-Path $output 'activation.json')
try {
    $sourceExecutable = Join-Path $package 'emule.exe'
    $sourceBuildInfo = Join-Path $package 'BUILD_INFO.txt'
    Assert-W12 (Test-Path -LiteralPath $sourceExecutable -PathType Leaf)
    Assert-W12 (Test-Path -LiteralPath $sourceBuildInfo -PathType Leaf)
    $expectedTemplateHash = Get-GitBlobSha256 -Repository $repository `
        -Commit $activation.activation_commit -RepositoryPath 'srchybrid/eMule.tmpl' `
        -TemporaryRoot $temporary
    foreach ($relativeTemplate in @('eMule.tmpl', 'config\eMule.tmpl')) {
        $sourceTemplate = Join-Path $package $relativeTemplate
        Assert-W12 (Test-Path -LiteralPath $sourceTemplate -PathType Leaf)
        Assert-W12 ((Get-Sha256File -Path $sourceTemplate) -ceq $expectedTemplateHash)
    }
    Assert-W12 (@(Get-ChildItem -LiteralPath $package -Recurse -Force | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    }).Count -eq 0)
    $sourceExecutableHash = Get-Sha256File -Path $sourceExecutable
    $sourceBuildInfoHash = Get-Sha256File -Path $sourceBuildInfo
    Get-ChildItem -LiteralPath $package -Force | ForEach-Object {
        Assert-W12 (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
        Assert-W12PrivateScratch -Path $scratch
        Copy-Item -LiteralPath $_.FullName -Destination $node -Recurse -Force
    }
    $executable = Join-Path $node 'emule.exe'
    $buildInfoPath = Join-Path $node 'BUILD_INFO.txt'
    Assert-W12 (Test-Path -LiteralPath $executable -PathType Leaf)
    Assert-W12 (Test-Path -LiteralPath $buildInfoPath -PathType Leaf)
    $buildInfo = Get-BuildInfo -Path $buildInfoPath
    # This is equality, deliberately not ancestry: the package BUILD_INFO is A.
    Assert-W12 ($buildInfo.commit -ceq $activation.activation_commit)
    $candidate.build_commit = $buildInfo.commit
    $candidate.release = $buildInfo.release
    $candidate.emule_sha256 = Get-Sha256File -Path $executable
    $candidate.build_info_sha256 = Get-Sha256File -Path $buildInfoPath
    Assert-W12 ($candidate.emule_sha256 -ceq $sourceExecutableHash)
    Assert-W12 ($candidate.build_info_sha256 -ceq $sourceBuildInfoHash)
    foreach ($relativeTemplate in @('eMule.tmpl', 'config\eMule.tmpl')) {
        Assert-W12 ((Get-Sha256File -Path (Join-Path $node $relativeTemplate)) -ceq $expectedTemplateHash)
    }
    $challenge = [ordered]@{
        schema = $challengeSchema
        candidate = $candidate
        binding = $binding
    }
    Write-W12Json -Value $challenge -Path (Join-Path $output 'browser-challenge.json')
    $ports = Resolve-W12Ports -RequestedWeb $WebPort -RequestedTcp $TcpPort -RequestedUdp $UdpPort
    $baseUri = [Uri]::new("http://127.0.0.1:$($ports.web)/")
    $password = 'w12-' + (Get-RandomHex -ByteCount 18)
    $null = $sensitiveValues.Add($password)
    $preferences = Join-Path $node 'config\preferences.ini'
    foreach ($item in @(
        @('eMule', 'AppVersion', 'eSE v9.2 W12 isolated runtime'),
        @('eMule', 'BindAddr', ''),
        @('eMule', 'Autoconnect', '0'),
        @('eMule', 'NetworkED2K', '0'),
        @('eMule', 'NetworkKademlia', '0'),
        @('eMule', 'Port', [string]$ports.tcp),
        @('eMule', 'UDPPort', [string]$ports.udp),
        @('eMule', 'SaveLogToDisk', '1'),
        @('eMule', 'SaveDebugToDisk', '1'),
        @('Connection', 'KadNetworkMask', '0'),
        @('UPnP', 'EnableUPnP', '0'),
        @('WebServer', 'Enabled', '1'),
        @('WebServer', 'Port', [string]$ports.web),
        @('WebServer', 'Password', (Get-Md5UnicodeText -Value $password)),
        @('WebServer', 'AllowedIPs', '127.0.0.1'),
        @('WebServer', 'WebUseUPnP', '0'),
        @('WebServer', 'UseHTTPS', '0'),
        @('WebServer', 'WebTimeoutMins', '10'),
        @('eSE', 'EseNetLabEnabled', '0'),
        @('KRPRelay', 'KrpRelayEnabled', '0'),
        @('KRPRelay', 'KrpRelayKillSwitch', '1')
    )) {
        Set-W12IniValue -Path $preferences -Section $item[0] -Key $item[1] -Value $item[2] -PrivateScratch $scratch
    }
    $httpHandler = [Net.Http.HttpClientHandler]::new()
    $httpHandler.AllowAutoRedirect = $false
    $httpHandler.UseCookies = $true
    $httpHandler.CookieContainer = [Net.CookieContainer]::new()
    $httpClient = [Net.Http.HttpClient]::new($httpHandler)
    $httpClient.Timeout = [TimeSpan]::FromSeconds(15)
    $process = Start-W12Node -Executable $executable -NodeRoot $node -TemporaryRoot $temporary -PrivateScratch $scratch -Ports $ports
    $ready = Wait-W12Ready -Client $httpClient -BaseUri $baseUri -Target $process -Seconds ([Math]::Min($TimeoutSeconds, 120))
    Assert-LoopbackListener -Port $ports.web -ProcessId $process.Id
    Set-W12Case -Id 'W12-RUNTIME-READY' -Status PASS -HttpStatus $ready.status -Checks @(
        'final portable binary answered', 'web listener was loopback-only', 'isolated ports were active'
    )
    $failureStage = 'W12-RUNTIME-LOGIN'
    $loginPath = '/?w=password&p=' + [Uri]::EscapeDataString($password)
    $loginReady = $false
    for ($loginAttempt = 0; $loginAttempt -lt 20; $loginAttempt++) {
        try {
        $login = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path $loginPath
        $csrf = Get-HeaderValue -Response $login -Name 'X-CSRF-Token'
        $setCookie = Get-HeaderValue -Response $login -Name 'Set-Cookie'
        $cookie = $httpHandler.CookieContainer.GetCookies($baseUri)['eSEWebSession']
        $loginReady = $login.status -eq 200 -and $csrf -match '^[0-9a-f]{64}$' -and
            $null -ne $cookie -and $cookie.Value -match '^[0-9a-f]{64}$' -and $cookie.HttpOnly -and
            $setCookie -match '(?i)eSEWebSession=[0-9a-f]{64};\s*Path=/;\s*HttpOnly;\s*SameSite=Strict'
        if ($loginReady) { break }
        } catch { $loginReady = $false }
        Start-Sleep -Milliseconds 250
    }
    Assert-W12 $loginReady
    Assert-W12 ($login.status -eq 200 -and $csrf -match '^[0-9a-f]{64}$')
    Assert-W12 ($null -ne $cookie -and $cookie.Value -match '^[0-9a-f]{64}$' -and $cookie.HttpOnly)
    Assert-W12 ($setCookie -match '(?i)eSEWebSession=[0-9a-f]{64};\s*Path=/;\s*HttpOnly;\s*SameSite=Strict')
    $null = $sensitiveValues.Add($csrf)
    $null = $sensitiveValues.Add($cookie.Value)
    Set-W12Case -Id 'W12-RUNTIME-LOGIN' -Status PASS -HttpStatus $login.status -Checks @(
        'classic loopback login succeeded', 'cookie was 256-bit HttpOnly SameSite Strict', 'CSRF was 256-bit'
    )
    $failureStage = 'W12-RUNTIME-BROADCAST'
    $start = Invoke-W12Http -Client $httpClient -BaseUri $baseUri `
        -Path '/api/live/broadcast/start?source=testpattern&title=W12&bitrate=1500' -Csrf $csrf
    $startJson = $start.text | ConvertFrom-Json
    $linkMatch = [regex]::Match([string]$startJson.link, '^ed2k://\|live\|(?<key>[0-9a-f]{32})\|')
    Assert-W12 ($start.status -eq 200 -and $startJson.success -eq $true -and
        $startJson.ready -eq $true -and [int]$startJson.chunks -ge 3 -and $linkMatch.Success)
    $streamKey = $linkMatch.Groups['key'].Value
    Set-W12Case -Id 'W12-RUNTIME-BROADCAST' -Status PASS -HttpStatus $start.status -Checks @(
        'testpattern start succeeded', 'at least three real HLS chunks existed', 'stream key was canonical'
    )
    $failureStage = 'W12-RUNTIME-PLAYER-CAPABILITY'
    $player = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path ("/live/$streamKey")
    Add-SensitiveResponse $player
    $capabilityPath = Get-CapabilityPath -Html $player.text -StreamKey $streamKey
    $capabilityToken = Get-CapabilityToken -CapabilityPath $capabilityPath
    $null = $sensitiveValues.Add($capabilityToken)
    Assert-W12 ($player.status -eq 200 -and (Test-HardenedResponse $player))
    Assert-W12 ($player.text -notmatch '/s/' -and $player.text -notmatch '/api/live/[0-9a-f]{32}/stream\.m3u8')
    Set-W12Case -Id 'W12-RUNTIME-PLAYER-CAPABILITY' -Status PASS -HttpStatus $player.status -Checks @(
        'cookie-authenticated player issued one capability', 'numeric session path was absent', 'response was hardened'
    )
    $failureStage = 'W12-RUNTIME-PLAYLIST'
    $playlist = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path $capabilityPath
    Add-SensitiveResponse $playlist
    Assert-W12 ($playlist.status -eq 200 -and $playlist.text.StartsWith('#EXTM3U') -and (Test-HardenedResponse $playlist))
    $mediaPlaylistPath = $capabilityPath
    if ($playlist.text -match '(?m)^stream_[0-4]\.m3u8\s*$') {
        $mediaLeaf = Get-PlaylistLeaf -Playlist $playlist.text -SuffixPattern '^stream_[0-4]\.m3u8$'
        $mediaPlaylistPath = New-CapabilityResourcePath -CapabilityPath $capabilityPath -Leaf $mediaLeaf
        $playlist = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path $mediaPlaylistPath
        Add-SensitiveResponse $playlist
        Assert-W12 ($playlist.status -eq 200 -and $playlist.text.StartsWith('#EXTM3U') -and (Test-HardenedResponse $playlist))
    }
    $segmentLeaf = Get-PlaylistLeaf -Playlist $playlist.text -SuffixPattern '^seg_(?:[0-4]_)?[0-9]{5,10}\.ts$'
    $segmentPath = New-CapabilityResourcePath -CapabilityPath $capabilityPath -Leaf $segmentLeaf
    $segment = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path $segmentPath
    Add-SensitiveResponse $segment
    Assert-W12 ($segment.status -eq 200 -and $segment.bytes.Length -gt 0 -and (Test-HardenedResponse $segment))
    Set-W12Case -Id 'W12-RUNTIME-PLAYLIST' -Status PASS -HttpStatus $playlist.status -Checks @(
        'capability playlist was fetched', 'resource grammar was canonical', 'non-empty segment was fetched'
    )
    $failureStage = 'W12-RUNTIME-RANGE'
    $rangeEnd = [Math]::Min(1023, $segment.bytes.Length - 1)
    $rangeText = "bytes=0-$rangeEnd"
    $rangeOne = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path $segmentPath -Range $rangeText
    $rangeTwo = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path $segmentPath -Range $rangeText
    Add-SensitiveResponse $rangeOne
    Add-SensitiveResponse $rangeTwo
    $expectedRange = New-Object byte[] ($rangeEnd + 1)
    [Array]::Copy($segment.bytes, 0, $expectedRange, 0, $expectedRange.Length)
    Assert-W12 ($rangeOne.status -eq 206 -and $rangeTwo.status -eq 206)
    Assert-W12 ([Convert]::ToBase64String($rangeOne.bytes) -ceq [Convert]::ToBase64String($expectedRange))
    Assert-W12 ([Convert]::ToBase64String($rangeOne.bytes) -ceq [Convert]::ToBase64String($rangeTwo.bytes))
    Assert-W12 ((Get-HeaderValue $rangeOne 'Content-Range') -ceq (Get-HeaderValue $rangeTwo 'Content-Range'))
    Assert-W12 ((Test-HardenedResponse $rangeOne) -and (Test-HardenedResponse $rangeTwo))
    Set-W12Case -Id 'W12-RUNTIME-RANGE' -Status PASS -HttpStatus $rangeOne.status -Checks @(
        'range returned 206', 'range matched full-body prefix byte-for-byte', 'retry bytes and metadata were exact'
    )
    $failureStage = 'W12-RUNTIME-FORGED-CAPABILITY'
    $forgedPath = $capabilityPath.Replace("/h/$capabilityToken/", "/h/$canary/")
    Assert-W12 ($forgedPath -cne $capabilityPath)
    $forged = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path $forgedPath
    Add-SensitiveResponse $forged
    $forgedBodyHits = [regex]::Matches($forged.text, [regex]::Escape($canary)).Count
    Assert-W12 ($forged.status -eq 403 -and $forgedBodyHits -eq 0 -and (Test-HardenedResponse $forged))
    Set-W12Case -Id 'W12-RUNTIME-FORGED-CAPABILITY' -Status PASS -HttpStatus $forged.status -Checks @(
        'canonical forged capability was rejected', 'rejection was no-store', 'rejection was no-referrer'
    )
    $failureStage = 'W12-RUNTIME-LOG-CANARY'
    $logResponse = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path '/api/live/log?n=500' -Csrf $csrf
    $canaryLogHits = [regex]::Matches($logResponse.text, [regex]::Escape($canary)).Count
    Assert-W12 ($logResponse.status -eq 200 -and $canaryLogHits -eq 0)
    Set-W12Case -Id 'W12-RUNTIME-LOG-CANARY' -Status PASS -HttpStatus $logResponse.status -Checks @(
        'application log was queried after rejection', 'raw canary had zero log hits'
    )
    $failureStage = 'W12-RUNTIME-LOGOUT-REVOCATION'
    $logout = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path '/?w=logout' -Csrf $csrf
    $afterLogout = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path $capabilityPath
    Add-SensitiveResponse $afterLogout
    Assert-W12 ($logout.status -eq 200 -and $afterLogout.status -eq 403 -and (Test-HardenedResponse $afterLogout))
    Set-W12Case -Id 'W12-RUNTIME-LOGOUT-REVOCATION' -Status PASS -HttpStatus $afterLogout.status -Checks @(
        'logout cleared the owner session', 'pre-logout capability was rejected', 'revocation response was hardened'
    )
    $failureStage = 'W12-RUNTIME-STOP-REVOCATION'
    $loginTwo = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path $loginPath
    $csrfTwo = Get-HeaderValue -Response $loginTwo -Name 'X-CSRF-Token'
    $cookieTwo = $httpHandler.CookieContainer.GetCookies($baseUri)['eSEWebSession']
    Assert-W12 ($loginTwo.status -eq 200 -and $csrfTwo -match '^[0-9a-f]{64}$' -and $null -ne $cookieTwo)
    $null = $sensitiveValues.Add($csrfTwo)
    $null = $sensitiveValues.Add($cookieTwo.Value)
    $playerTwo = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path ("/live/$streamKey")
    Add-SensitiveResponse $playerTwo
    $capabilityTwo = Get-CapabilityPath -Html $playerTwo.text -StreamKey $streamKey
    $null = $sensitiveValues.Add((Get-CapabilityToken $capabilityTwo))
    $stop = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path '/api/live/broadcast/stop' -Csrf $csrfTwo
    $afterStop = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path $capabilityTwo
    Add-SensitiveResponse $afterStop
    Assert-W12 ($stop.status -eq 200 -and ($stop.text | ConvertFrom-Json).success -eq $true)
    Assert-W12 ($afterStop.status -eq 403 -and (Test-HardenedResponse $afterStop))
    Set-W12Case -Id 'W12-RUNTIME-STOP-REVOCATION' -Status PASS -HttpStatus $afterStop.status -Checks @(
        'broadcast stop succeeded', 'pre-stop capability was rejected', 'stale source caused no HLS success'
    )
    $failureStage = 'W12-RUNTIME-ROLLOVER-REVOCATION'
    $restartBroadcast = Invoke-W12Http -Client $httpClient -BaseUri $baseUri `
        -Path '/api/live/broadcast/start?source=testpattern&title=W12-Rollover&bitrate=1500' -Csrf $csrfTwo
    $restartJson = $restartBroadcast.text | ConvertFrom-Json
    $restartMatch = [regex]::Match([string]$restartJson.link, '^ed2k://\|live\|(?<key>[0-9a-f]{32})\|')
    Assert-W12 ($restartBroadcast.status -eq 200 -and $restartJson.ready -eq $true -and $restartMatch.Success)
    $rolloverKey = $restartMatch.Groups['key'].Value
    $playerThree = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path ("/live/$rolloverKey")
    Add-SensitiveResponse $playerThree
    $capabilityThree = Get-CapabilityPath -Html $playerThree.text -StreamKey $rolloverKey
    $null = $sensitiveValues.Add((Get-CapabilityToken $capabilityThree))
    $newPlaylist = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path $capabilityThree
    $oldAfterRollover = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path $capabilityTwo
    Add-SensitiveResponse $newPlaylist
    Add-SensitiveResponse $oldAfterRollover
    Assert-W12 ($newPlaylist.status -eq 200 -and $oldAfterRollover.status -eq 403)
    Assert-W12 ((Test-HardenedResponse $newPlaylist) -and (Test-HardenedResponse $oldAfterRollover))
    Set-W12Case -Id 'W12-RUNTIME-ROLLOVER-REVOCATION' -Status PASS -HttpStatus $oldAfterRollover.status -Checks @(
        'new generation issued a working capability', 'old generation remained rejected', 'both responses were hardened'
    )
    $failureStage = 'W12-BROWSER-HANDSHAKE'
    # Browser handoff: raw credentials/challenge values and raw CDP stay in scratch.
    # The documented Node REPL collector consumes ready/handoff, claims the ready
    # hash, and writes only raw/done in scratch; this A-materialized verifier normalizes.
    $handoff = [ordered]@{
        schema = $handoffSchema
        A = $binding.activation_commit
        candidate = $candidate
        binding = $binding
        base_url = $baseUri.AbsoluteUri
        login_password = $password
        stream_key = $rolloverKey
        canary = $canary
        run_id = $runId
        challenge_nonce = $challengeNonce
        raw_path = [IO.Path]::GetFullPath($browserRawTrace)
        done_path = [IO.Path]::GetFullPath($browserDone)
    }
    Write-W12Json -Value $handoff -Path $browserHandoff -PrivateScratch $exchange -ScratchKind Exchange
    Write-W12Json -Value $handoff -Path $browserHandoffVerifier -PrivateScratch $scratch
    $ready = [ordered]@{
        schema = $readySchema
        A = $binding.activation_commit
        run_id_sha256 = $binding.run_id_sha256
        challenge_nonce_sha256 = $binding.challenge_nonce_sha256
        handoff_sha256 = Get-Sha256File -Path $browserHandoff
        collector_sha256 = $activation.tool_sha256.collector
    }
    Write-W12Json -Value $ready -Path $browserReady -PrivateScratch $exchange -ScratchKind Exchange
    $browserReadyFull = [IO.Path]::GetFullPath($browserReady)
    Assert-W12 ($browserReadyFull -eq [IO.Path]::GetFullPath((Join-Path $exchange 'browser-ready.json')))
    Assert-W12 (@(Get-ChildItem -LiteralPath $exchange -Filter 'browser-ready.json' -File -Force).Count -eq 1)
    # This is the sole machine-readable rendezvous marker.  The path is inside
    # the ACL-isolated exchange and the ready document contains hashes only.
    Write-Output ('W12_BROWSER_READY=' + $browserReadyFull)
    Wait-W12BrowserEvidence -Scratch $exchange -RawPath $browserRawTrace -DonePath $browserDone -ClaimPath $browserClaim `
        -Seconds ([Math]::Min($TimeoutSeconds, 180))
    $pythonCommand = Get-Command python.exe -ErrorAction Stop
    $evidenceVerifier = Join-Path $scratch 'verify_w12_security_evidence.py'
    Export-W12GitBlob -Repository $repository -Commit $activation.activation_commit `
        -RepositoryPath 'tools/architecture/verify_w12_security_evidence.py' -Destination $evidenceVerifier `
        -PrivateScratch $scratch -ExpectedSha256 $activation.tool_sha256.verifier
    $challengePath = Join-Path $output 'browser-challenge.json'
    & $pythonCommand.Source $evidenceVerifier --activation (Join-Path $output 'activation.json') --normalize-collector $browserRawTrace --handoff $browserHandoffVerifier `
        --ready $browserReady --done-signal $browserDone --challenge $challengePath --output $browserTrace
    Assert-W12 ($LASTEXITCODE -eq 0)
    $traceText = Get-Content -LiteralPath $browserTrace -Raw -Encoding UTF8
    Assert-W12 ($traceText -notmatch '(?i)esewebsession=|x-csrf-token|https?://127\.0\.0\.1|/h/[0-9a-f]{64}/')
    foreach ($secret in @($runId, $challengeNonce, $canary, $password, $rolloverKey)) {
        Assert-W12 ($traceText.IndexOf($secret, [StringComparison]::Ordinal) -lt 0)
    }
    $browserHandshakeComplete = $true
    foreach ($transient in @($browserHandoff, $browserHandoffVerifier, $browserReady, $browserClaim, $browserRawTrace, $browserDone, $evidenceVerifier)) {
        if (Test-Path -LiteralPath $transient) { Remove-Item -LiteralPath $transient -Force }
    }
    $failureStage = 'W12-RUNTIME-RESTART-REVOCATION'
    $firstStop = Stop-W12ProcessTree -Target $process -NodeRoot $node
    $process = $null
    Assert-W12 $firstStop
    $process = Start-W12Node -Executable $executable -NodeRoot $node -TemporaryRoot $temporary -PrivateScratch $scratch -Ports $ports
    $null = Wait-W12Ready -Client $httpClient -BaseUri $baseUri -Target $process -Seconds ([Math]::Min($TimeoutSeconds, 120))
    Assert-LoopbackListener -Port $ports.web -ProcessId $process.Id
    $afterRestart = Invoke-W12Http -Client $httpClient -BaseUri $baseUri -Path $capabilityThree
    Add-SensitiveResponse $afterRestart
    Assert-W12 ($afterRestart.status -eq 403 -and (Test-HardenedResponse $afterRestart))
    Set-W12Case -Id 'W12-RUNTIME-RESTART-REVOCATION' -Status PASS -HttpStatus $afterRestart.status -Checks @(
        'same portable node restarted', 'pre-restart capability was rejected', 'restart rejection was hardened'
    )
    $flowSucceeded = $true
} catch {
    $flowSucceeded = $false
} finally {
    if ($null -ne $process) {
        try {
            $terminationConfirmed = Stop-W12ProcessTree -Target $process -NodeRoot $node
        } catch {
            $terminationConfirmed = $false
        }
        $process = $null
    }
    if ($null -ne $httpClient) { try { $httpClient.Dispose() } catch { }; $httpClient = $null }
    if ($null -ne $httpHandler) { try { $httpHandler.Dispose() } catch { }; $httpHandler = $null }
}
if ($terminationConfirmed) {
    Set-W12Case -Id 'W12-RUNTIME-TERMINATION' -Status PASS -HttpStatus $null -Checks @(
        'primary process exited', 'portable-node child processes exited'
    )
} else {
    Set-W12Case -Id 'W12-RUNTIME-TERMINATION' -Status FAIL -HttpStatus $null -Checks @('process termination was not confirmed')
    if ($flowSucceeded) { $failureStage = 'W12-RUNTIME-TERMINATION' }
    $flowSucceeded = $false
}
try {
    foreach ($transient in @($browserHandoff, $browserHandoffVerifier, $browserReady, $browserClaim, $browserRawTrace, $browserDone, $evidenceVerifier)) {
        Assert-W12 (-not (Test-Path -LiteralPath $transient))
    }
    Assert-W12 $browserHandshakeComplete
    $scan = Scan-W12Artifacts -Root $output -Secrets @($sensitiveValues) -Canary $canary
    $canaryArtifactHits = $scan.canary_hits
    $secretsPersisted = $scan.secret_hits -ne 0
    $sensitiveUrlsPersisted = $scan.sensitive_url_hits -ne 0
    if ($canaryArtifactHits -eq 0 -and -not $secretsPersisted -and -not $sensitiveUrlsPersisted) {
        Set-W12Case -Id 'W12-RUNTIME-ARTIFACT-SCAN' -Status PASS -HttpStatus $null -Checks @(
            'raw credential and capability hits were zero', 'raw canary hits were zero', 'sensitive URL hits were zero'
        )
    } else {
        Set-W12Case -Id 'W12-RUNTIME-ARTIFACT-SCAN' -Status FAIL -HttpStatus $null -Checks @('sensitive artifact scan found persisted material')
        if ($flowSucceeded) { $failureStage = 'W12-RUNTIME-ARTIFACT-SCAN' }
        $flowSucceeded = $false
    }
} catch {
    Set-W12Case -Id 'W12-RUNTIME-ARTIFACT-SCAN' -Status FAIL -HttpStatus $null -Checks @('sensitive artifact scan did not complete')
    if ($flowSucceeded) { $failureStage = 'W12-RUNTIME-ARTIFACT-SCAN' }
    $flowSucceeded = $false
}
try {
    $scratchFull = [IO.Path]::GetFullPath($scratch)
    $exchangeFull = [IO.Path]::GetFullPath($exchange)
    Assert-W12 ($null -ne $scratchParentPrefix -and
        $scratchFull.StartsWith($scratchParentPrefix, [StringComparison]::OrdinalIgnoreCase))
    Assert-W12 ($null -ne $exchangeParentPrefix -and
        $exchangeFull.StartsWith($exchangeParentPrefix, [StringComparison]::OrdinalIgnoreCase))
    Assert-W12 (-not $scratchFull.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase))
    Assert-W12 (-not $exchangeFull.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase))
    Assert-W12PrivateScratch -Path $scratchFull
    Assert-W12ExchangeScratch -Path $exchangeFull
    Remove-Item -LiteralPath $scratchFull -Recurse -Force
    Remove-Item -LiteralPath $exchangeFull -Recurse -Force
    $scratchRemoved = -not (Test-Path -LiteralPath $scratchFull) -and
        -not (Test-Path -LiteralPath $exchangeFull)
} catch {
    $scratchRemoved = $false
    $flowSucceeded = $false
    $failureStage = 'W12-RUNTIME-ARTIFACT-SCAN'
}
$noStore = $sensitiveResponses.Count -gt 0
$noReferrer = $sensitiveResponses.Count -gt 0
foreach ($response in $sensitiveResponses) {
    $noStore = $noStore -and ((Get-HeaderValue $response 'Cache-Control') -match '(?i)(?:^|,)\s*no-store\s*(?:,|$)')
    $noReferrer = $noReferrer -and ((Get-HeaderValue $response 'Referrer-Policy').Trim().ToLowerInvariant() -eq 'no-referrer')
}
if (-not $noStore -or -not $noReferrer -or $canaryLogHits -ne 0 -or $forgedBodyHits -ne 0 -or -not $scratchRemoved) {
    $flowSucceeded = $false
}
foreach ($id in $caseOrder) {
    if (-not $caseResults.Contains($id)) {
        $caseResults[$id] = [ordered]@{
            id = $id
            status = 'FAIL'
            http_status = $null
            checks = @('case was not executed to completion')
        }
    }
}
$orderedCases = @($caseOrder | ForEach-Object { $caseResults[$_] })
$allCasesPass = @($orderedCases | Where-Object { $_.status -ne 'PASS' }).Count -eq 0
$verdict = if ($flowSucceeded -and $allCasesPass) { 'PASS' } else { 'FAIL' }
if ($verdict -eq 'PASS') { $failureStage = $null }
$summary = [ordered]@{
    schema = $runtimeSchema
    candidate = $candidate
    execution = [ordered]@{
        loopback_only = $true
        portable = $true
        headless = $true
        process_termination_confirmed = $terminationConfirmed
        scratch_removed = $scratchRemoved
    }
    cases = $orderedCases
    canary = [ordered]@{
        sha256 = $canarySha256
        log_hits = $canaryLogHits
        artifact_hits = $canaryArtifactHits
        forged_body_hits = $forgedBodyHits
    }
    privacy = [ordered]@{
        no_store_all_sensitive_responses = $noStore
        no_referrer_all_sensitive_responses = $noReferrer
        secrets_persisted = $secretsPersisted
        sensitive_urls_persisted = $sensitiveUrlsPersisted
    }
    binding = $binding
    verdict = $verdict
}
$summaryPath = Join-Path $output 'runtime.json'
Write-W12Json -Value $summary -Path $summaryPath
if ($verdict -ne 'PASS') { throw "W12 security runtime FAIL at $failureStage; inspect sanitized runtime.json" }
Write-Host 'W12 security runtime PASS'
} finally {
    if ($null -ne $process) {
        try { $null = Stop-W12ProcessTree -Target $process -NodeRoot $node } catch { }
        $process = $null
    }
    foreach ($transient in @($browserHandoff, $browserHandoffVerifier, $browserReady, $browserClaim, $browserRawTrace, $browserDone, $evidenceVerifier)) {
        if ($null -ne $transient -and (Test-Path -LiteralPath $transient)) {
            try { Remove-Item -LiteralPath $transient -Force -ErrorAction Stop } catch { }
        }
    }
    if ($null -ne $browserTrace -and -not $browserHandshakeComplete -and (Test-Path -LiteralPath $browserTrace -PathType Leaf)) {
        try { Remove-Item -LiteralPath $browserTrace -Force -ErrorAction Stop } catch { }
    }
    if ($null -ne $scratch -and (Test-Path -LiteralPath $scratch -PathType Container)) {
        $scratchFull = [IO.Path]::GetFullPath($scratch)
        if ($null -ne $scratchParentPrefix -and
            $scratchFull.StartsWith($scratchParentPrefix, [StringComparison]::OrdinalIgnoreCase) -and
            -not $scratchFull.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            try { Remove-Item -LiteralPath $scratchFull -Recurse -Force -ErrorAction Stop } catch { }
        }
    }
    if ($null -ne $exchange -and (Test-Path -LiteralPath $exchange -PathType Container)) {
        $exchangeFull = [IO.Path]::GetFullPath($exchange)
        if ($null -ne $exchangeParentPrefix -and
            $exchangeFull.StartsWith($exchangeParentPrefix, [StringComparison]::OrdinalIgnoreCase) -and
            -not $exchangeFull.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            try { Remove-Item -LiteralPath $exchangeFull -Recurse -Force -ErrorAction Stop } catch { }
        }
    }
}
