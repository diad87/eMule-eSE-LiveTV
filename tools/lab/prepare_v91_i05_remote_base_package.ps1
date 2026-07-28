[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Rc2ZipPath,
    [string]$OutputZip = '',
    [switch]$ValidateOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$expected = [ordered]@{
    release = 'v0.70b-eSE9.1.0-rc.2'
    commit = '08aa6521f7d7907edb3584266abc3a9e31693161'
    archive_name = 'eSE-LiveTV-v0.70b-eSE9.1.0-rc.2-x64.zip'
    archive_bytes = 212025531L
    archive_sha256 =
        '5F17AF0EDBDDA9E1FCC165D2E2F8A33910B40F856343934B970DB24259CF3590'
    emule_bytes = 11250688L
    emule_sha256 =
        '55C5AA0E968B25330720CFB7F622CBC28EA9875365145333CBCF9D9585C1C44A'
    ese_server_bytes = 70502379L
    ese_server_sha256 =
        'EECEEF0F0DBE427F3667C033E2B653FC69E432ABCC3E8AFAF996840A7315E568'
    build_info_bytes = 501L
    build_info_sha256 =
        '7C87F77268030C2B4DA40C6DA8C960F968B4E1A033C9987B64E45C49CF4B5915'
    sha256_sums_bytes = 14401L
    sha256_sums_sha256 =
        '8A39593E8503A1B3B7C0E2F284111C308F716BD995109E816EF9EE43CFE370C9'
    ffmpeg_bytes = 223360000L
    ffmpeg_sha256 =
        'D1E2A156261ECC675081943197A85F08F2868784A0AF499171EDE89353EDAD31'
    fixture_bytes = 4294967296L
    fixture_sha256 =
        '1016D6F63AE1649A879A7C0DE30865ED132DEB37B1C3B2BC9CA004C88FEEE26C'
    fixture_ed2k = '796A95E75DF8E78D54A57CDEA1FEDE84'
    fixture_full_repetitions = 19
    fixture_trailing_bytes = 51127296L
}

function Get-I05BaseFullPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Label path is required."
    }
    return [IO.Path]::GetFullPath($Path)
}

function Get-I05Sha256FromStream {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha256.ComputeHash($Stream))).Replace('-', '')
    } finally {
        $sha256.Dispose()
    }
}

function Assert-I05ArchiveEntry {
    param(
        [Parameter(Mandatory = $true)]$Archive,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][Int64]$Bytes,
        [Parameter(Mandatory = $true)][string]$Sha256
    )

    $matches = @($Archive.Entries | Where-Object {
        $_.FullName -ceq $Name
    })
    if ($matches.Count -ne 1) {
        throw "RC2 archive must contain exactly one '$Name' entry."
    }
    $entry = $matches[0]
    if ([Int64]$entry.Length -ne $Bytes) {
        throw "RC2 '$Name' byte length mismatch: $($entry.Length)"
    }
    $stream = $entry.Open()
    try {
        $actual = Get-I05Sha256FromStream -Stream $stream
    } finally {
        $stream.Dispose()
    }
    if ($actual -ne $Sha256) {
        throw "RC2 '$Name' SHA-256 mismatch: $actual"
    }
    return $entry
}

function Read-I05ZipTextEntry {
    param(
        [Parameter(Mandatory = $true)]$Archive,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $entry = $Archive.GetEntry($Name)
    if ($null -eq $entry) {
        throw "Missing text entry '$Name'."
    }
    $stream = $entry.Open()
    $reader = New-Object IO.StreamReader(
        $stream, (New-Object Text.UTF8Encoding($false)), $true)
    try {
        return $reader.ReadToEnd()
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Add-I05ZipFileStreaming {
    param(
        [Parameter(Mandatory = $true)]$Archive,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$EntryName,
        [Parameter(Mandatory = $true)]$Compression
    )

    $entry = $Archive.CreateEntry($EntryName, $Compression)
    $input = [IO.File]::OpenRead($Source)
    $output = $entry.Open()
    try {
        $input.CopyTo($output, 1048576)
    } finally {
        $output.Dispose()
        $input.Dispose()
    }
}

function Add-I05ZipText {
    param(
        [Parameter(Mandatory = $true)]$Archive,
        [Parameter(Mandatory = $true)][string]$EntryName,
        [Parameter(Mandatory = $true)][string]$Text
    )

    $entry = $Archive.CreateEntry(
        $EntryName, [IO.Compression.CompressionLevel]::Optimal)
    $stream = $entry.Open()
    $writer = New-Object IO.StreamWriter(
        $stream, (New-Object Text.UTF8Encoding($false)))
    try {
        $writer.Write($Text)
    } finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}

Add-Type -AssemblyName System.IO.Compression

$archivePath = Get-I05BaseFullPath -Path $Rc2ZipPath -Label 'RC2 ZIP'
if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    throw "Exact RC2 ZIP is missing: $archivePath"
}
$archiveItem = Get-Item -LiteralPath $archivePath
if ($archiveItem.Length -ne $expected.archive_bytes) {
    throw "RC2 ZIP byte length mismatch: $($archiveItem.Length)"
}
$archiveHash =
    (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
if ($archiveHash -ne $expected.archive_sha256) {
    throw "RC2 ZIP SHA-256 mismatch: $archiveHash"
}

$releaseStream = [IO.File]::OpenRead($archivePath)
$releaseArchive = New-Object IO.Compression.ZipArchive(
    $releaseStream, [IO.Compression.ZipArchiveMode]::Read, $false)
try {
    $null = Assert-I05ArchiveEntry -Archive $releaseArchive `
        -Name 'emule.exe' -Bytes $expected.emule_bytes `
        -Sha256 $expected.emule_sha256
    $null = Assert-I05ArchiveEntry -Archive $releaseArchive `
        -Name 'ese-server.exe' -Bytes $expected.ese_server_bytes `
        -Sha256 $expected.ese_server_sha256
    $null = Assert-I05ArchiveEntry -Archive $releaseArchive `
        -Name 'BUILD_INFO.txt' -Bytes $expected.build_info_bytes `
        -Sha256 $expected.build_info_sha256
    $null = Assert-I05ArchiveEntry -Archive $releaseArchive `
        -Name 'SHA256SUMS.txt' -Bytes $expected.sha256_sums_bytes `
        -Sha256 $expected.sha256_sums_sha256
    $null = Assert-I05ArchiveEntry -Archive $releaseArchive `
        -Name 'ffmpeg.exe' -Bytes $expected.ffmpeg_bytes `
        -Sha256 $expected.ffmpeg_sha256

    $buildInfo = Read-I05ZipTextEntry `
        -Archive $releaseArchive -Name 'BUILD_INFO.txt'
    $releasePattern =
        '(?m)^release:\s*' + [regex]::Escape($expected.release) + '\s*$'
    $commitPattern =
        '(?m)^commit:\s*' + [regex]::Escape($expected.commit) + '\s*$'
    if ($buildInfo -notmatch $releasePattern -or
        $buildInfo -notmatch $commitPattern -or
        $buildInfo -notmatch '(?m)^dirty:\s*false\s*$') {
        throw 'RC2 BUILD_INFO.txt does not attest the pinned clean release.'
    }
} finally {
    $releaseArchive.Dispose()
    $releaseStream.Dispose()
}

$generatorPath = Join-Path $PSScriptRoot `
    'ensure_v91_i05_canonical_fixture.ps1'
if (-not (Test-Path -LiteralPath $generatorPath -PathType Leaf)) {
    throw "Canonical fixture generator is missing: $generatorPath"
}
$generatorItem = Get-Item -LiteralPath $generatorPath
$generatorHash =
    (Get-FileHash -LiteralPath $generatorPath -Algorithm SHA256).Hash

$manifest = [ordered]@{
    schema = 'ese.v91.i05-remote-base/v1'
    case_id = 'V91-I05'
    created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    purpose = 'Pinned RC2 payload and canonical fixture tooling for the physical T1 IPv4 control'
    candidate = [ordered]@{
        release = $expected.release
        commit = $expected.commit
        dirty = $false
        archive_entry =
            "payload/$($expected.archive_name)"
        archive_name = $expected.archive_name
        archive_bytes = $expected.archive_bytes
        archive_sha256 =
            $expected.archive_sha256.ToLowerInvariant()
        emule = [ordered]@{
            path = 'emule.exe'
            bytes = $expected.emule_bytes
            sha256 = $expected.emule_sha256.ToLowerInvariant()
        }
        ese_server = [ordered]@{
            path = 'ese-server.exe'
            bytes = $expected.ese_server_bytes
            sha256 = $expected.ese_server_sha256.ToLowerInvariant()
        }
        build_info = [ordered]@{
            path = 'BUILD_INFO.txt'
            bytes = $expected.build_info_bytes
            sha256 = $expected.build_info_sha256.ToLowerInvariant()
        }
        sha256_sums = [ordered]@{
            path = 'SHA256SUMS.txt'
            bytes = $expected.sha256_sums_bytes
            sha256 = $expected.sha256_sums_sha256.ToLowerInvariant()
        }
        ffmpeg = [ordered]@{
            path = 'ffmpeg.exe'
            bytes = $expected.ffmpeg_bytes
            sha256 = $expected.ffmpeg_sha256.ToLowerInvariant()
        }
    }
    canonical_fixture = [ordered]@{
        generator_entry =
            'tools/lab/ensure_v91_i05_canonical_fixture.ps1'
        generator_bytes = [Int64]$generatorItem.Length
        generator_sha256 = $generatorHash.ToLowerInvariant()
        seed_package_path = 'ffmpeg.exe'
        seed_bytes = $expected.ffmpeg_bytes
        seed_sha256 = $expected.ffmpeg_sha256.ToLowerInvariant()
        full_repetitions = $expected.fixture_full_repetitions
        trailing_bytes = $expected.fixture_trailing_bytes
        bytes = $expected.fixture_bytes
        sha256 = $expected.fixture_sha256.ToLowerInvariant()
        ed2k = $expected.fixture_ed2k
    }
    measurement = [ordered]@{
        topology = 'T1'
        transport_family = 'IPv4'
        physical_windows_hosts_required = 2
        application_ipv6_mode = 'Off'
        windows_ipv6_stack_must_remain_enabled = $true
        preflight_ipv6_lan_probe_required = $true
        overlays_are_control_plane_only = $true
        overlay_data_path_is_formal_pass = $false
    }
}

if ($ValidateOnly) {
    if (-not [string]::IsNullOrWhiteSpace($OutputZip)) {
        throw 'OutputZip must be omitted with -ValidateOnly.'
    }
    [pscustomobject]@{
        status = 'VALIDATED'
        manifest = [pscustomobject]$manifest
    }
    return
}

$outputPath = Get-I05BaseFullPath -Path $OutputZip -Label 'Output ZIP'
if ([IO.Path]::GetExtension($outputPath) -ne '.zip') {
    throw 'OutputZip must end in .zip.'
}
if ($outputPath.Equals(
        $archivePath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputZip must differ from the pinned RC2 ZIP.'
}
if (Test-Path -LiteralPath $outputPath) {
    throw "Refusing to overwrite an existing ZIP: $outputPath"
}
$outputParent = Split-Path -Parent $outputPath
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    throw "Output ZIP parent directory does not exist: $outputParent"
}

$outputStream = [IO.File]::Open(
    $outputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite,
    [IO.FileShare]::None)
$outputArchive = New-Object IO.Compression.ZipArchive(
    $outputStream, [IO.Compression.ZipArchiveMode]::Create, $false)
try {
    Add-I05ZipFileStreaming -Archive $outputArchive `
        -Source $archivePath `
        -EntryName "payload/$($expected.archive_name)" `
        -Compression ([IO.Compression.CompressionLevel]::NoCompression)
    Add-I05ZipFileStreaming -Archive $outputArchive `
        -Source $generatorPath `
        -EntryName 'tools/lab/ensure_v91_i05_canonical_fixture.ps1' `
        -Compression ([IO.Compression.CompressionLevel]::Optimal)
    Add-I05ZipText -Archive $outputArchive `
        -EntryName 'I05-BASE-MANIFEST.json' `
        -Text ($manifest | ConvertTo-Json -Depth 10)
} catch {
    $outputArchive.Dispose()
    $outputStream.Dispose()
    Remove-Item -LiteralPath $outputPath -Force -ErrorAction SilentlyContinue
    throw
} finally {
    try { $outputArchive.Dispose() } catch {}
    try { $outputStream.Dispose() } catch {}
}

$outputHash =
    (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash
[pscustomobject]@{
    status = 'CREATED'
    path = $outputPath
    bytes = [Int64](Get-Item -LiteralPath $outputPath).Length
    sha256 = $outputHash.ToLowerInvariant()
    manifest = [pscustomobject]$manifest
}
