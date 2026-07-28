[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [Parameter(Mandatory = $true)][string]$NodePath
)

$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$NodePath = (Resolve-Path -LiteralPath $NodePath).Path

$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$temporaryRoot = Join-Path $temporaryBase (
    'ese-v92-l08-runtime-' + [Guid]::NewGuid().ToString('N')
)
$resolvedTemporary = [IO.Path]::GetFullPath($temporaryRoot)
if (-not $resolvedTemporary.StartsWith(
        $temporaryBase + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "L08 temporary path escaped the system temporary directory"
}
New-Item -ItemType Directory -Path $resolvedTemporary | Out-Null

function Assert-L08NoSecret {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string[]]$Secrets,
        [Parameter(Mandatory = $true)][string]$Surface
    )
    foreach ($secret in $Secrets) {
        if ($Text.Contains($secret)) {
            throw "L08 privacy leak in ${Surface}: $secret"
        }
    }
}

try {
    $nodeOutput = @(
        & $NodePath --test (
            Join-Path $RepoRoot 'tests\test_v92_l08_privacy_runtime.js'
        ) 2>&1
    )
    if ($LASTEXITCODE -ne 0) {
        throw "L08 runtime projection failed:`n$($nodeOutput -join "`n")"
    }
    $nodeText = ($nodeOutput | ForEach-Object { [string]$_ }) -join "`n"
    if ($nodeText -notmatch '(?m)^# pass 2$' -or
        $nodeText -notmatch '(?m)^# fail 0$') {
        throw "L08 runtime projection did not execute exactly two passing tests"
    }

    $ownerToken = 'owner-runtime-7f29c1'
    $nonce = 'abcdef0123456789abcdef01'
    $ipv4 = '192.168.71.23'
    $ipv6 = '2001:db8:71::23'
    $gatewayFingerprint = 'gateway-runtime-fingerprint-9321'
    $secrets = @(
        $ownerToken, $nonce, $ipv4, $ipv6, $gatewayFingerprint
    )

    $runDirectory = Join-Path $resolvedTemporary 'report-run'
    New-Item -ItemType Directory -Path $runDirectory | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $runDirectory 'evidence.json'),
        '{"schema":"ese.v92.l08.fixture/v1","verdict":"PASS"}',
        [Text.UTF8Encoding]::new($false)
    )
    $reportJson = Join-Path $resolvedTemporary 'REPORT-L08.json'
    $reportMarkdown = Join-Path $resolvedTemporary 'REPORT-L08.md'
    $notes = (
        'owner_token={0} nonce={1} ip={2} ' +
        'gateway_fingerprint={3} ' +
        '{{"owner_token":"{0}","nonce":"{1}",' +
        '"gateway_fingerprint":"{3}","ip":"{2}","ipv6":"{4}"}}'
    ) -f $ownerToken, $nonce, $ipv4, $gatewayFingerprint, $ipv6
    & (Join-Path $RepoRoot 'tools\lab\collect_report.ps1') `
        -RunDirectory $runDirectory -CaseId 'L08-RUNTIME' -Outcome PASS `
        -Notes $notes -OutFile $reportJson -MarkdownOut $reportMarkdown |
        Out-Null
    $reportText = (
        (Get-Content -LiteralPath $reportJson -Raw) + "`n" +
        (Get-Content -LiteralPath $reportMarkdown -Raw)
    )
    Assert-L08NoSecret -Text $reportText -Secrets $secrets -Surface 'report'
    foreach ($marker in @(
            '<redacted>', '<redacted-ipv4>', '<redacted-ipv6>')) {
        if (-not $reportText.Contains($marker)) {
            throw "L08 report is missing expected privacy marker: $marker"
        }
    }

    . (Join-Path $RepoRoot 'tools\release_zip_integrity.ps1')
    $package = Join-Path $resolvedTemporary 'package'
    New-Item -ItemType Directory -Path $package | Out-Null
    $payload = Join-Path $package 'payload.txt'
    [IO.File]::WriteAllText(
        $payload, 'L08 deterministic ZIP payload',
        [Text.UTF8Encoding]::new($false)
    )
    $payloadHash = (
        Get-FileHash -LiteralPath $payload -Algorithm SHA256
    ).Hash.ToUpperInvariant()
    [IO.File]::WriteAllText(
        (Join-Path $package 'SHA256SUMS.txt'),
        "$payloadHash  payload.txt`r`n",
        [Text.ASCIIEncoding]::new()
    )
    $validZip = Join-Path $resolvedTemporary 'valid.zip'
    Compress-Archive -Path (Join-Path $package '*') `
        -DestinationPath $validZip -CompressionLevel Optimal
    Test-ReleaseZipIntegrity -SourceDirectory $package -Archive $validZip `
        -VerificationRoot $resolvedTemporary | Out-Null

    $tamperedPackage = Join-Path $resolvedTemporary 'tampered-package'
    New-Item -ItemType Directory -Path $tamperedPackage | Out-Null
    Copy-Item -LiteralPath (Join-Path $package 'SHA256SUMS.txt') `
        -Destination $tamperedPackage
    [IO.File]::WriteAllText(
        (Join-Path $tamperedPackage 'payload.txt'),
        'L08 altered payload',
        [Text.UTF8Encoding]::new($false)
    )
    $tamperedZip = Join-Path $resolvedTemporary 'tampered.zip'
    Compress-Archive -Path (Join-Path $tamperedPackage '*') `
        -DestinationPath $tamperedZip -CompressionLevel Optimal
    $tamperedRejected = $false
    try {
        Test-ReleaseZipIntegrity -SourceDirectory $tamperedPackage `
            -Archive $tamperedZip -VerificationRoot $resolvedTemporary |
            Out-Null
    } catch {
        $tamperedRejected = $true
    }
    if (-not $tamperedRejected) {
        throw 'L08 ZIP verifier accepted an altered payload with a stale manifest'
    }

    $scriptGraph = @(
        'tests\test_v92_l08_privacy_runtime.ps1',
        'tools\lab\collect_report.ps1',
        'tools\lab\common.ps1',
        'tools\release_zip_integrity.ps1'
    )
    $forbiddenCommands = @(
        'Start-Process', 'Read-Host', 'Get-Credential',
        'Add-MpPreference', 'Set-MpPreference', 'Checkpoint-Computer'
    )
    foreach ($relative in $scriptGraph) {
        $path = Join-Path $RepoRoot $relative
        $tokens = $null
        $parseErrors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            $path, [ref]$tokens, [ref]$parseErrors
        )
        if ($parseErrors.Count -ne 0) {
            throw "L08 command graph contains invalid PowerShell: $relative"
        }
        $source = Get-Content -LiteralPath $path -Raw
        if ($source -match '(?im)^\s*#requires\s+-RunAsAdministrator\b' -or
            $source -match '(?i)\b-Verb\s+RunAs\b') {
            throw "L08 command graph requires elevation: $relative"
        }
        $commands = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() } |
            Where-Object { $_ })
        foreach ($forbidden in $forbiddenCommands) {
            if ($commands -contains $forbidden) {
                throw "L08 command graph is interactive or privileged: $relative -> $forbidden"
            }
        }
    }

    Write-Output (
        'L08_RUNTIME_PASS node=2 report=1 zip_positive=1 ' +
        'zip_negative=1 command_graph=4'
    )
} finally {
    if (Test-Path -LiteralPath $resolvedTemporary) {
        $deleteTarget = [IO.Path]::GetFullPath($resolvedTemporary)
        if (-not $deleteTarget.StartsWith(
                $temporaryBase + '\',
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove an unsafe L08 temporary path'
        }
        Remove-Item -LiteralPath $deleteTarget -Recurse -Force
    }
}
