[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$VanillaExe,
    [Parameter(Mandatory = $true)][string]$VanillaTemplate,
    [Parameter(Mandatory = $true)][string]$Fixture,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.\d{1,3}\.\d{1,3}$')]
    [string]$CoordinatorTailscaleIPv4,
    [Parameter(Mandatory = $true)][string]$OutputZip,
    [ValidateRange(30, 1440)][int]$ValidityMinutes = 480
)

$ErrorActionPreference = 'Stop'

$expected = [ordered]@{
    emule_bytes = 7896576L
    emule_sha256 =
        '1FD7EEB62E9A93914644DC4FBD11E0C7AC37EE0A416EDF90F415EED7D9A7C105'
    template_bytes = 115017L
    template_sha256 =
        '09E4C42F069F06EE77C0A2185A84265DCF08A00A5805CDD197741C2DE742C08E'
    fixture_name = 'net13-unique-ffmpeg.zip'
    fixture_bytes = 223394208L
    fixture_sha256 =
        'AAC4B00281982E473AAB7071B1A593EEF3AD22301085D18D26933557B022890C'
    fixture_ed2k = 'A4140C71628D93D5FD0981FD962C2552'
}

function Resolve-PinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$Bytes,
        [Parameter(Mandatory = $true)][string]$Sha256,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $item = Get-Item -LiteralPath $resolved
    if ($item.Length -ne $Bytes) {
        throw "$Label byte length mismatch."
    }
    $actual = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
    if ($actual -ne $Sha256) {
        throw "$Label SHA-256 mismatch."
    }
    return $resolved
}

function Add-ZipFileStreaming {
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

function Add-ZipText {
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

$emule = Resolve-PinnedFile -Path $VanillaExe `
    -Bytes $expected.emule_bytes -Sha256 $expected.emule_sha256 `
    -Label 'vanilla emule.exe'
$template = Resolve-PinnedFile -Path $VanillaTemplate `
    -Bytes $expected.template_bytes -Sha256 $expected.template_sha256 `
    -Label 'vanilla eMule.tmpl'
$fixturePath = Resolve-PinnedFile -Path $Fixture `
    -Bytes $expected.fixture_bytes -Sha256 $expected.fixture_sha256 `
    -Label 'compatibility fixture'
if ((Split-Path -Leaf $fixturePath) -ne $expected.fixture_name) {
    throw "Fixture filename must be '$($expected.fixture_name)'."
}

$requiredScripts = @(
    'run_v91_c01_vanilla_source_kit.ps1',
    'cleanup_v91_c01_vanilla_source.ps1',
    'START-V91-C01-VANILLA.cmd',
    'STOP-V91-C01-VANILLA.cmd'
)
foreach ($name in $requiredScripts) {
    if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $name) `
            -PathType Leaf)) {
        throw "Missing V91-C01 kit script: $name"
    }
}

$output = [IO.Path]::GetFullPath($OutputZip)
if ([IO.Path]::GetExtension($output) -ne '.zip') {
    throw 'OutputZip must end in .zip.'
}
if (Test-Path -LiteralPath $output) {
    throw "Refusing to overwrite existing ZIP: $output"
}
$parent = Split-Path -Parent $output
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $parent -Force
}

$created = [DateTimeOffset]::UtcNow
$config = [ordered]@{
    schema = 'ese.v91.c01-remote-kit-config/v1'
    case_id = 'V91-C01'
    kit_nonce = [Guid]::NewGuid().ToString('N')
    created_at_utc = $created.ToString('o')
    expires_at_utc = $created.AddMinutes($ValidityMinutes).ToString('o')
    coordinator_tailscale_ipv4 = $CoordinatorTailscaleIPv4
    vanilla = [ordered]@{
        version = '0.70b'
        emule_bytes = $expected.emule_bytes
        emule_sha256 = $expected.emule_sha256.ToLowerInvariant()
        template_bytes = $expected.template_bytes
        template_sha256 = $expected.template_sha256.ToLowerInvariant()
    }
    fixture = [ordered]@{
        name = $expected.fixture_name
        bytes = $expected.fixture_bytes
        sha256 = $expected.fixture_sha256.ToLowerInvariant()
        ed2k = $expected.fixture_ed2k
    }
    transport = 'Tailscale IPv4 overlay'
    purpose = 'V91-C01 classic-wire interoperability only'
}

Add-Type -AssemblyName System.IO.Compression
$zipStream = [IO.File]::Open(
    $output, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite,
    [IO.FileShare]::None)
$archive = New-Object IO.Compression.ZipArchive(
    $zipStream, [IO.Compression.ZipArchiveMode]::Create, $false)
try {
    Add-ZipFileStreaming -Archive $archive -Source $emule `
        -EntryName 'node/emule.exe' `
        -Compression ([IO.Compression.CompressionLevel]::Optimal)
    Add-ZipFileStreaming -Archive $archive -Source $template `
        -EntryName 'node/eMule.tmpl' `
        -Compression ([IO.Compression.CompressionLevel]::Optimal)
    Add-ZipFileStreaming -Archive $archive -Source $fixturePath `
        -EntryName "node/Incoming/$($expected.fixture_name)" `
        -Compression ([IO.Compression.CompressionLevel]::NoCompression)
    foreach ($name in $requiredScripts) {
        Add-ZipFileStreaming -Archive $archive `
            -Source (Join-Path $PSScriptRoot $name) `
            -EntryName "tools/lab/$name" `
            -Compression ([IO.Compression.CompressionLevel]::Optimal)
    }
    Add-ZipText -Archive $archive -EntryName 'C01-REMOTE-CONFIG.json' `
        -Text ($config | ConvertTo-Json -Depth 8)
} catch {
    $archive.Dispose()
    $zipStream.Dispose()
    Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue
    throw
} finally {
    try { $archive.Dispose() } catch {}
    try { $zipStream.Dispose() } catch {}
}

$zipHash = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash
Write-Host "V91-C01 remote ZIP ready: $output" -ForegroundColor Green
Write-Host "ZIP SHA-256: $zipHash"
Write-Host "Kit nonce: $($config.kit_nonce)"
