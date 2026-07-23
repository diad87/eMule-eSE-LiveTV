# Deterministic-input portable package for eSE v9 prereleases.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ReleaseTag,
    [string]$RepoRoot = '',
    [string]$FfmpegPath = '',
    [switch]$AllowDirty
)

$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path } }
$RepoRoot = (Resolve-Path $RepoRoot).Path

$preflightArgs = @{ ReleaseTag = $ReleaseTag; RepoRoot = $RepoRoot }
if ($AllowDirty) { $preflightArgs.AllowDirty = $true }
& (Join-Path $RepoRoot 'tools\release_preflight.ps1') @preflightArgs

# release_preflight has already validated this exact tag grammar. Derive the
# matching notes filename here so alpha, beta and RC packages cannot silently
# copy the notes from a different prerelease.
$ReleaseTag -match '^v0\.70b-eSE(?<version>.+)$' | Out-Null
$releaseVersion = $Matches.version
$releaseNotesRelativePath = "docs\RELEASE_NOTES_v$releaseVersion.md"
$testerNick = switch -Regex ($releaseVersion) {
    '-alpha\.' { 'eSE-Alpha-Tester'; break }
    '-beta\.'  { 'eSE-Beta-Tester'; break }
    '-rc\.'    { 'eSE-RC-Tester'; break }
    default    { 'eSE-Tester' }
}

$distRoot = Join-Path $RepoRoot 'dist'
$releaseRoot = Join-Path $distRoot $ReleaseTag
$packageDir = Join-Path $releaseRoot 'package'
$zipPath = Join-Path $releaseRoot "eSE-LiveTV-$ReleaseTag-x64.zip"
$resolvedDist = [IO.Path]::GetFullPath($distRoot).TrimEnd('\') + '\'
$resolvedRelease = [IO.Path]::GetFullPath($releaseRoot).TrimEnd('\') + '\'
if (-not $resolvedRelease.StartsWith($resolvedDist, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to prepare an output outside dist: $resolvedRelease"
}
if (Test-Path $releaseRoot) { Remove-Item -LiteralPath $releaseRoot -Recurse -Force }
New-Item -ItemType Directory $packageDir -Force | Out-Null

function Require-Copy([string]$Source, [string]$Destination) {
    if (-not (Test-Path $Source -PathType Leaf)) { throw "Required release input missing: $Source" }
    $parent = Split-Path -Parent $Destination
    if ($parent) { New-Item -ItemType Directory $parent -Force | Out-Null }
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}
function Copy-Tree([string]$Source, [string]$Destination) {
    if (-not (Test-Path $Source -PathType Container)) { throw "Required release directory missing: $Source" }
    New-Item -ItemType Directory $Destination -Force | Out-Null
    Get-ChildItem -LiteralPath $Source -Force | Where-Object { $_.Name -ne 'node_modules' } | Copy-Item -Destination $Destination -Recurse -Force
}
function Hash([string]$Path) { return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant() }

Write-Host '[1/7] Fresh binaries'
Require-Copy (Join-Path $RepoRoot 'srchybrid\x64\Release\emule.exe') (Join-Path $packageDir 'emule.exe')
Require-Copy (Join-Path $RepoRoot 'srchybrid\eSE\ese-server.exe') (Join-Path $packageDir 'ese-server.exe')

$langSource = Join-Path $RepoRoot 'srchybrid\x64\lang'
$langDlls = @(Get-ChildItem (Join-Path $langSource '*.dll') -ErrorAction SilentlyContinue)
if ($langDlls.Count -eq 0) { throw 'No freshly built language DLLs found.' }
$langDir = Join-Path $packageDir 'lang'
New-Item -ItemType Directory $langDir -Force | Out-Null
foreach ($dll in $langDlls) { Copy-Item -LiteralPath $dll.FullName -Destination (Join-Path $langDir $dll.Name) -Force }

Write-Host '[2/7] Pinned media toolchain'
$inputs = Get-Content (Join-Path $RepoRoot 'tools\release_inputs.json') -Raw | ConvertFrom-Json
if (-not $FfmpegPath) {
    $ffmpegCommand = Get-Command ffmpeg.exe -ErrorAction SilentlyContinue
    if ($ffmpegCommand) { $FfmpegPath = $ffmpegCommand.Source }
}
if (-not $FfmpegPath -or -not (Test-Path $FfmpegPath -PathType Leaf)) {
    throw 'Pinned ffmpeg.exe not found. Pass -FfmpegPath explicitly.'
}
$FfmpegPath = (Resolve-Path $FfmpegPath).Path
$ffprobePath = Join-Path (Split-Path -Parent $FfmpegPath) 'ffprobe.exe'
if (-not (Test-Path $ffprobePath -PathType Leaf)) { throw "ffprobe.exe missing next to $FfmpegPath" }
if ((Hash $FfmpegPath) -ne $inputs.ffmpeg.sha256.ToUpperInvariant()) { throw 'ffmpeg.exe SHA-256 does not match tools/release_inputs.json' }
if ((Hash $ffprobePath) -ne $inputs.ffprobe.sha256.ToUpperInvariant()) { throw 'ffprobe.exe SHA-256 does not match tools/release_inputs.json' }
$ffmpegVersionLine = (& $FfmpegPath -version 2>&1 | Select-Object -First 1)
if ($ffmpegVersionLine -notmatch [regex]::Escape($inputs.ffmpeg.version)) { throw "Unexpected FFmpeg version: $ffmpegVersionLine" }
Require-Copy $FfmpegPath (Join-Path $packageDir 'ffmpeg.exe')
Require-Copy $ffprobePath (Join-Path $packageDir 'ffprobe.exe')

Write-Host '[3/7] Dashboard source assets'
$eseSource = Join-Path $RepoRoot 'srchybrid\eSE'
$eseDest = Join-Path $packageDir 'eSE'
New-Item -ItemType Directory $eseDest -Force | Out-Null
foreach ($pattern in @('*.js','*.json','*.html','*.svg','*.ico')) {
    Get-ChildItem (Join-Path $eseSource $pattern) -File -ErrorAction SilentlyContinue | Copy-Item -Destination $eseDest -Force
}
foreach ($directory in @('pages','routes','shared','eSE-live')) {
    Copy-Tree (Join-Path $eseSource $directory) (Join-Path $eseDest $directory)
}

Write-Host '[4/7] Canonical configuration'
$configDir = Join-Path $packageDir 'config'
New-Item -ItemType Directory $configDir -Force | Out-Null
Require-Copy (Join-Path $RepoRoot 'srchybrid\eMule.tmpl') (Join-Path $packageDir 'eMule.tmpl')
Require-Copy (Join-Path $RepoRoot 'srchybrid\eMule.tmpl') (Join-Path $configDir 'eMule.tmpl')

$nodesBytes = [Convert]::FromBase64String((Get-Content (Join-Path $RepoRoot 'srchybrid\config\nodes.dat.b64') -Raw).Trim())
$nodesExpected = (Get-Content (Join-Path $RepoRoot 'srchybrid\config\nodes.dat.sha256') -Raw).Trim().ToUpperInvariant()
$sha = [Security.Cryptography.SHA256]::Create()
try { $nodesActual = ([BitConverter]::ToString($sha.ComputeHash($nodesBytes))).Replace('-', '') }
finally { $sha.Dispose() }
if ($nodesExpected -notmatch '^[0-9A-F]{64}$' -or $nodesActual -ne $nodesExpected) { throw 'Pinned nodes.dat SHA-256 validation failed.' }
if ($nodesBytes.Length -lt 100 -or $nodesBytes.Length -gt 5MB) { throw 'Pinned nodes.dat has an invalid size.' }
[IO.File]::WriteAllBytes((Join-Path $configDir 'nodes.dat'), $nodesBytes)

@(
    '[eMule]',
    "Nick=$testerNick",
    'Port=4662',
    'UDPPort=4672',
    'Autoconnect=1',
    'AutoStart=1',
    'Networks=eD2K|Kad',
    "[UPnP]",
    "EnableUPnP=1",
    "[WebServer]",
    'Enabled=1',
    'Port=4711',
    'Password=',
    "WebUseUPnP=0",
    "[eSE]",
    'EseNetLabConsent=0',
    'EseNetLabEnabled=0',
    "EseV9Experimental=0",
    'EseKad3Rendezvous=0',
    'EseAutoKeepalive=0',
    'EseRelayAccept=0',
    'EseRelayEgress=0',
    'EseReachSelector=0',
    'EseHolePunchPortPredict=0',
    'EseEd2kPunch3=0',
    'Kad6PublicExitOptIn=0',
    '[KRPRelay]',
    'KrpRelayEnabled=0',
    'KrpRelayKillSwitch=0',
    'ExperimentalTcpDataPlane=0'
) | Out-File (Join-Path $configDir 'preferences.ini') -Encoding ASCII

Write-Host '[5/7] License, help and release notes'
foreach ($mapping in @(
    @('README.md','README.md'),
    @('license.txt','license.txt'),
    @('THIRD_PARTY_LICENSES.md','THIRD_PARTY_LICENSES.md'),
    @('docs\USER_GUIDE.md','USER_GUIDE.md'),
    @($releaseNotesRelativePath,'RELEASE_NOTES.md')
)) {
    Require-Copy (Join-Path $RepoRoot $mapping[0]) (Join-Path $packageDir $mapping[1])
}
if (Test-Path (Join-Path $RepoRoot 'tools\update_check.ps1')) {
    Require-Copy (Join-Path $RepoRoot 'tools\update_check.ps1') (Join-Path $packageDir 'tools\update_check.ps1')
}

Write-Host '[6/7] Build provenance and file manifest'
$gitSha = (& git -C $RepoRoot rev-parse HEAD).Trim()
$dirty = @(& git -C $RepoRoot status --porcelain=v1 --untracked-files=all --ignore-submodules=none)
$dirtyText = if ($dirty.Count -eq 0) { 'false' } else { 'true (development override)' }
$nodeVersion = (& node --version 2>$null)
$npmVersion = (& npm.cmd --version 2>$null)
@(
    "release: $ReleaseTag",
    "commit: $gitSha",
    "dirty: $dirtyText",
    "built_utc: $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
    "node: $nodeVersion",
    "npm: $npmVersion",
    "ffmpeg: $ffmpegVersionLine",
    "ffmpeg_sha256: $(Hash (Join-Path $packageDir 'ffmpeg.exe'))",
    "ffprobe_sha256: $(Hash (Join-Path $packageDir 'ffprobe.exe'))",
    "nodes_dat_sha256: $nodesActual"
) | Out-File (Join-Path $packageDir 'BUILD_INFO.txt') -Encoding ASCII

$manifestPath = Join-Path $packageDir 'SHA256SUMS.txt'
$manifestLines = @(Get-ChildItem $packageDir -Recurse -File | Where-Object { $_.FullName -ne $manifestPath } | Sort-Object FullName | ForEach-Object {
    $relative = $_.FullName.Substring($packageDir.Length + 1).Replace('\','/')
    "$(Hash $_.FullName)  $relative"
})
$manifestLines | Out-File $manifestPath -Encoding ASCII

Write-Host '[7/7] ZIP and external checksum'
Compress-Archive -Path (Join-Path $packageDir '*') -DestinationPath $zipPath -CompressionLevel Optimal -Force
$zipHash = Hash $zipPath
"$zipHash  $([IO.Path]::GetFileName($zipPath))" | Out-File "$zipPath.sha256" -Encoding ASCII
Write-Host "Package: $packageDir" -ForegroundColor Green
Write-Host "ZIP:     $zipPath" -ForegroundColor Green
Write-Host "SHA256:  $zipHash" -ForegroundColor Green
