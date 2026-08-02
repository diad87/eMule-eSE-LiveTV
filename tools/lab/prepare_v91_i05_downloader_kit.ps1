[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RemoteBaseZip,
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$expectedArchiveName =
    'eSE-LiveTV-v0.70b-eSE9.1.0-rc.3-x64.zip'
$expectedArchiveBytes = 212040831L
$expectedArchiveSha256 =
    '359272c764c532c32cfd97eeb92e2db4feaa620c5d3f6318a82a7453dbf1b56f'
$minimumFreeBytes = 10737418240L

$commonPath = Join-Path $PSScriptRoot 'common.ps1'
$contractPath = Join-Path $PSScriptRoot 'v91_i05_t1_contract.ps1'
foreach ($required in @($commonPath, $contractPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Falta la dependencia del preparador: $required"
    }
}
. $commonPath
. $contractPath

function Get-I05KitSafePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Relative
    )
    $target = [IO.Path]::GetFullPath((Join-Path $Root $Relative))
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/') + '\'
    if (-not $target.StartsWith(
            $prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "La entrada escapa del kit: $Relative"
    }
    return $target
}

$baseZip = [IO.Path]::GetFullPath($RemoteBaseZip)
$config = [IO.Path]::GetFullPath($ConfigPath)
$output = [IO.Path]::GetFullPath($OutputDirectory)
foreach ($input in @($baseZip, $config)) {
    if (-not (Test-Path -LiteralPath $input -PathType Leaf)) {
        throw "No existe el input: $input"
    }
    if (((Get-Item -LiteralPath $input -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "El input no puede ser reparse point: $input"
    }
}
if (Test-Path -LiteralPath $output) {
    throw 'OutputDirectory debe ser nuevo.'
}
$parent = Split-Path -Parent $output
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw 'El padre de OutputDirectory no existe.'
}
$root = [IO.Path]::GetPathRoot($output)
if ($root -notmatch '^(?<drive>[A-Za-z]):\\$') {
    throw 'El kit H3 debe prepararse en una unidad local con letra.'
}
$drive = $Matches['drive']
$volume = Get-Volume -DriveLetter $drive -ErrorAction Stop
$disk = Get-CimInstance Win32_LogicalDisk `
    -Filter "DeviceID='$drive`:'" -ErrorAction Stop
if ([string]$volume.FileSystemType -cne 'NTFS' -or
    [int]$disk.DriveType -ne 3 -or
    [Int64]$disk.FreeSpace -lt $minimumFreeBytes) {
    throw 'OutputDirectory requiere NTFS local fijo y al menos 10 GiB.'
}

$configRaw = Get-Content -LiteralPath $config -Raw
$configDocument = $configRaw | ConvertFrom-Json
Assert-I05ExactText -Actual ([string]$configDocument.schema) `
    -Expected 'ese.v91.i05.t1-config/v1' -Context 'CONFIG schema'
Assert-I05ExactText -Actual ([string]$configDocument.case_id) `
    -Expected 'V91-I05' -Context 'CONFIG case'
Assert-I05ExactText -Actual ([string]$configDocument.status) `
    -Expected 'ARMED' -Context 'CONFIG status'
$null = Assert-I05Nonce -Value $configDocument.nonce `
    -Context 'CONFIG nonce'
Assert-I05CandidateContract -Candidate $configDocument.candidate `
    -Context 'CONFIG.candidate'
if ([string]$configDocument.source.host_id_sha256 -notmatch
        '^[0-9a-f]{64}$' -or
    [string]$configDocument.source.interface_id -notmatch
        '^[0-9a-f]{12}$' -or
    [string]$configDocument.ipv6_probe.source_interface_id -cne
        [string]$configDocument.source.interface_id) {
    throw 'CONFIG no ata host/interface H1 IPv4 e IPv6.'
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($baseZip)
try {
    $manifestEntries = @($archive.Entries | Where-Object {
        $_.FullName -ceq 'I05-BASE-MANIFEST.json'
    })
    if ($manifestEntries.Count -ne 1) {
        throw 'El paquete base no contiene un manifiesto unico.'
    }
    $reader = New-Object IO.StreamReader(
        $manifestEntries[0].Open(),
        (New-Object Text.UTF8Encoding($false)), $true)
    try {
        $baseManifest = $reader.ReadToEnd() | ConvertFrom-Json
    } finally {
        $reader.Dispose()
    }
    Assert-I05ExactText -Actual ([string]$baseManifest.schema) `
        -Expected 'ese.v91.i05-remote-base/v1' `
        -Context 'Base manifest schema'
    Assert-I05ExactText -Actual (
        ([string]$baseManifest.candidate.archive_sha256).ToLowerInvariant()
    ) -Expected $expectedArchiveSha256 `
        -Context 'Base manifest RC3 ZIP SHA'
    if ([Int64]$baseManifest.candidate.archive_bytes -ne
            $expectedArchiveBytes) {
        throw 'Base manifest RC3 ZIP bytes no coincide.'
    }
    $candidateEntryName =
        [string]$baseManifest.candidate.archive_entry
    $candidateEntries = @($archive.Entries | Where-Object {
        $_.FullName -ceq $candidateEntryName
    })
    if ($candidateEntries.Count -ne 1 -or
        [Int64]$candidateEntries[0].Length -ne $expectedArchiveBytes) {
        throw 'El ZIP RC3 nested no es unico/exacto por tamano.'
    }
    foreach ($entry in $archive.Entries) {
        $null = Get-I05KitSafePath -Root $output `
            -Relative $entry.FullName
    }
} finally {
    $archive.Dispose()
}

$null = New-Item -ItemType Directory -Path $output
try {
    [IO.Compression.ZipFile]::ExtractToDirectory($baseZip, $output)
    $nestedArchive = Join-Path $output (
        "payload\candidates\$expectedArchiveName")
    if (-not (Test-Path -LiteralPath $nestedArchive -PathType Leaf) -or
        [Int64](Get-Item -LiteralPath $nestedArchive).Length -ne
            $expectedArchiveBytes -or
        (Get-LabSha256 -Path $nestedArchive) -cne
            $expectedArchiveSha256) {
        throw 'El ZIP RC3 extraido no coincide en bytes/SHA-256.'
    }

    $dependencies = @(
        'START-V91-I05-DOWNLOADER.cmd',
        'STOP-V91-I05-DOWNLOADER.cmd',
        'run_v91_i05_downloader_kit.ps1',
        'cleanup_v91_i05_downloader.ps1',
        'selftest_v91_i05_downloader.ps1',
        'ensure_v91_i05_canonical_fixture.ps1',
        'common.ps1',
        'prepare_node.ps1',
        'v91_i05_t1_contract.ps1'
    )
    foreach ($name in $dependencies) {
        $source = Join-Path $PSScriptRoot $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Falta la dependencia H3 '$name'."
        }
        Copy-Item -LiteralPath $source `
            -Destination (Join-Path $output $name)
    }
    [IO.File]::WriteAllText(
        (Join-Path $output 'V91-I05-T1-CONFIG.json'),
        $configRaw,
        (New-Object Text.UTF8Encoding($false)))

    $files = @(
        Get-ChildItem -LiteralPath $output -File -Recurse |
            Sort-Object FullName | ForEach-Object {
                [ordered]@{
                    path = $_.FullName.Substring(
                        $output.TrimEnd('\').Length + 1).Replace('\', '/')
                    bytes = [Int64]$_.Length
                    sha256 = Get-LabSha256 -Path $_.FullName
                }
            }
    )
    $kitManifest = [ordered]@{
        schema = 'ese.v91.i05.t1-h3-kit/v1'
        case_id = 'V91-I05'
        status = 'PREPARED'
        created_at_utc = Get-LabUtcTimestamp
        nonce_sha256 =
            Get-LabStringSha256 -Value ([string]$configDocument.nonce)
        candidate = $configDocument.candidate
        storage = [ordered]@{
            filesystem = 'NTFS'
            fixed_local = $true
            free_bytes_at_prepare = [Int64]$disk.FreeSpace
            minimum_free_bytes = $minimumFreeBytes
        }
        entry_points = [ordered]@{
            start = 'START-V91-I05-DOWNLOADER.cmd'
            stop = 'STOP-V91-I05-DOWNLOADER.cmd'
        }
        files = $files
    }
    $manifestPath = Write-LabJson -Value $kitManifest `
        -Path (Join-Path $output 'I05-H3-KIT-MANIFEST.json')
    [pscustomobject]@{
        status = 'PREPARED'
        path = $output
        manifest = $manifestPath
        manifest_sha256 = Get-LabSha256 -Path $manifestPath
        file_count = $files.Count
    }
} catch {
    if (Test-Path -LiteralPath $output -PathType Container) {
        Remove-Item -LiteralPath $output -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
    throw
}
