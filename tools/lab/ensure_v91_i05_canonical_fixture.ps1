[CmdletBinding()]
param(
    [ValidateSet('SelfTest', 'Create', 'Verify')]
    [string]$Mode = 'Verify',
    [string]$SeedPath = '',
    [string]$FixturePath = '',
    [string]$ReportPath = '',
    [ValidateRange(0, 1099511627776)]
    [Int64]$MinimumFreeAfterBytes = 268435456
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$expected = [ordered]@{
    seed_name = 'ffmpeg.exe'
    seed_bytes = 223360000L
    seed_sha256 =
        'D1E2A156261ECC675081943197A85F08F2868784A0AF499171EDE89353EDAD31'
    fixture_bytes = 4294967296L
    fixture_sha256 =
        '1016D6F63AE1649A879A7C0DE30865ED132DEB37B1C3B2BC9CA004C88FEEE26C'
    fixture_ed2k = '796A95E75DF8E78D54A57CDEA1FEDE84'
    full_repetitions = 19
    trailing_bytes = 51127296L
}

function Initialize-I05FixtureHashType {
    if ('EseV91Lab.CanonicalFixture' -as [type]) {
        return
    }

    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EseV91Lab
{
    public sealed class FixtureHashResult
    {
        public long Bytes { get; private set; }
        public string Sha256 { get; private set; }
        public string Ed2k { get; private set; }

        internal FixtureHashResult(long bytes, string sha256, string ed2k)
        {
            Bytes = bytes;
            Sha256 = sha256;
            Ed2k = ed2k;
        }
    }

    public static class CanonicalFixture
    {
        private const int Ed2kPartSize = 9728000;
        private const int BufferSize = 4 * 1024 * 1024;

        public static FixtureHashResult HashFile(string path)
        {
            if (String.IsNullOrWhiteSpace(path))
                throw new ArgumentException("A file path is required.", "path");

            using (FileStream input = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.Read,
                BufferSize, FileOptions.SequentialScan))
            {
                return HashStream(input);
            }
        }

        public static FixtureHashResult CreateRepeatedFile(
            string seedPath,
            string targetPath,
            int fullRepetitions,
            long trailingBytes)
        {
            if (String.IsNullOrWhiteSpace(seedPath))
                throw new ArgumentException("A seed path is required.", "seedPath");
            if (String.IsNullOrWhiteSpace(targetPath))
                throw new ArgumentException("A target path is required.", "targetPath");
            if (fullRepetitions < 0)
                throw new ArgumentOutOfRangeException("fullRepetitions");
            if (trailingBytes < 0)
                throw new ArgumentOutOfRangeException("trailingBytes");

            using (FileStream seed = new FileStream(
                seedPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                BufferSize, FileOptions.SequentialScan))
            {
                if (seed.Length == 0)
                    throw new InvalidDataException("The seed file is empty.");
                if (trailingBytes > seed.Length)
                    throw new InvalidDataException(
                        "Trailing bytes exceed the seed length.");

                using (FileStream output = new FileStream(
                    targetPath, FileMode.CreateNew, FileAccess.Write,
                    FileShare.None, BufferSize, FileOptions.SequentialScan))
                using (SHA256 sha256 = SHA256.Create())
                {
                    Ed2kState ed2k = new Ed2kState();
                    byte[] buffer = new byte[BufferSize];
                    long written = 0;

                    for (int repetition = 0;
                         repetition < fullRepetitions;
                         ++repetition)
                    {
                        seed.Position = 0;
                        CopyExactly(
                            seed, output, seed.Length, buffer, sha256, ed2k,
                            ref written);
                    }

                    if (trailingBytes != 0)
                    {
                        seed.Position = 0;
                        CopyExactly(
                            seed, output, trailingBytes, buffer, sha256, ed2k,
                            ref written);
                    }

                    sha256.TransformFinalBlock(new byte[0], 0, 0);
                    output.Flush(true);

                    return new FixtureHashResult(
                        written,
                        ToHex(sha256.Hash),
                        ToHex(ed2k.Finish()));
                }
            }
        }

        public static string Md4Hex(byte[] value)
        {
            if (value == null)
                throw new ArgumentNullException("value");
            Md4State md4 = new Md4State();
            md4.Update(value, 0, value.Length);
            return ToHex(md4.Finish());
        }

        private static FixtureHashResult HashStream(Stream input)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                Ed2kState ed2k = new Ed2kState();
                byte[] buffer = new byte[BufferSize];
                long total = 0;
                int read;

                while ((read = input.Read(buffer, 0, buffer.Length)) != 0)
                {
                    sha256.TransformBlock(buffer, 0, read, buffer, 0);
                    ed2k.Update(buffer, 0, read);
                    total += read;
                }

                sha256.TransformFinalBlock(new byte[0], 0, 0);
                return new FixtureHashResult(
                    total,
                    ToHex(sha256.Hash),
                    ToHex(ed2k.Finish()));
            }
        }

        private static void CopyExactly(
            Stream input,
            Stream output,
            long count,
            byte[] buffer,
            HashAlgorithm sha256,
            Ed2kState ed2k,
            ref long written)
        {
            long remaining = count;
            while (remaining != 0)
            {
                int wanted = (int)Math.Min((long)buffer.Length, remaining);
                int read = input.Read(buffer, 0, wanted);
                if (read == 0)
                    throw new EndOfStreamException(
                        "The pinned seed ended before the requested recipe.");

                output.Write(buffer, 0, read);
                sha256.TransformBlock(buffer, 0, read, buffer, 0);
                ed2k.Update(buffer, 0, read);
                written += read;
                remaining -= read;
            }
        }

        private static string ToHex(byte[] value)
        {
            StringBuilder result = new StringBuilder(value.Length * 2);
            for (int i = 0; i < value.Length; ++i)
                result.Append(value[i].ToString("X2"));
            return result.ToString();
        }

        private sealed class Ed2kState
        {
            private readonly List<byte[]> parts = new List<byte[]>();
            private Md4State current = new Md4State();
            private int currentBytes;
            private long totalBytes;
            private bool finished;

            public void Update(byte[] value, int offset, int count)
            {
                if (finished)
                    throw new InvalidOperationException(
                        "The ED2K state is already finalized.");
                if (value == null)
                    throw new ArgumentNullException("value");
                if (offset < 0 || count < 0 ||
                    offset > value.Length - count)
                    throw new ArgumentOutOfRangeException("offset");

                while (count != 0)
                {
                    int take = Math.Min(count, Ed2kPartSize - currentBytes);
                    current.Update(value, offset, take);
                    currentBytes += take;
                    totalBytes += take;
                    offset += take;
                    count -= take;

                    if (currentBytes == Ed2kPartSize)
                    {
                        parts.Add(current.Finish());
                        current = new Md4State();
                        currentBytes = 0;
                    }
                }
            }

            public byte[] Finish()
            {
                if (finished)
                    throw new InvalidOperationException(
                        "The ED2K state is already finalized.");
                finished = true;

                if (currentBytes != 0 || parts.Count == 0)
                {
                    parts.Add(current.Finish());
                }
                else if (totalBytes != 0 &&
                         totalBytes % Ed2kPartSize == 0)
                {
                    // eMule includes a trailing empty part when the length is
                    // an exact multiple of PARTSIZE.
                    parts.Add(current.Finish());
                }

                if (parts.Count == 1)
                    return parts[0];

                Md4State root = new Md4State();
                for (int i = 0; i < parts.Count; ++i)
                    root.Update(parts[i], 0, parts[i].Length);
                return root.Finish();
            }
        }

        private sealed class Md4State
        {
            private uint a = 0x67452301U;
            private uint b = 0xefcdab89U;
            private uint c = 0x98badcfeU;
            private uint d = 0x10325476U;
            private readonly byte[] pending = new byte[64];
            private int pendingBytes;
            private long totalBytes;
            private bool finished;

            public void Update(byte[] value, int offset, int count)
            {
                if (finished)
                    throw new InvalidOperationException(
                        "The MD4 state is already finalized.");
                if (value == null)
                    throw new ArgumentNullException("value");
                if (offset < 0 || count < 0 ||
                    offset > value.Length - count)
                    throw new ArgumentOutOfRangeException("offset");

                totalBytes += count;

                if (pendingBytes != 0)
                {
                    int take = Math.Min(count, 64 - pendingBytes);
                    Buffer.BlockCopy(
                        value, offset, pending, pendingBytes, take);
                    pendingBytes += take;
                    offset += take;
                    count -= take;
                    if (pendingBytes == 64)
                    {
                        ProcessBlock(pending, 0);
                        pendingBytes = 0;
                    }
                }

                while (count >= 64)
                {
                    ProcessBlock(value, offset);
                    offset += 64;
                    count -= 64;
                }

                if (count != 0)
                {
                    Buffer.BlockCopy(value, offset, pending, 0, count);
                    pendingBytes = count;
                }
            }

            public byte[] Finish()
            {
                if (finished)
                    throw new InvalidOperationException(
                        "The MD4 state is already finalized.");

                ulong bitLength = unchecked((ulong)totalBytes * 8UL);
                int paddingBytes =
                    pendingBytes < 56 ? 56 - pendingBytes : 120 - pendingBytes;
                byte[] padding = new byte[paddingBytes];
                padding[0] = 0x80;
                Update(padding, 0, padding.Length);

                byte[] length = new byte[8];
                for (int i = 0; i < length.Length; ++i)
                    length[i] = (byte)(bitLength >> (8 * i));
                Update(length, 0, length.Length);

                if (pendingBytes != 0)
                    throw new InvalidOperationException(
                        "MD4 finalization left a partial block.");

                finished = true;
                byte[] result = new byte[16];
                WriteUInt32(result, 0, a);
                WriteUInt32(result, 4, b);
                WriteUInt32(result, 8, c);
                WriteUInt32(result, 12, d);
                return result;
            }

            private void ProcessBlock(byte[] value, int offset)
            {
                uint[] x = new uint[16];
                for (int i = 0; i < x.Length; ++i)
                {
                    int at = offset + i * 4;
                    x[i] =
                        (uint)value[at] |
                        ((uint)value[at + 1] << 8) |
                        ((uint)value[at + 2] << 16) |
                        ((uint)value[at + 3] << 24);
                }

                uint aa = a;
                uint bb = b;
                uint cc = c;
                uint dd = d;

                unchecked
                {
                    a = FF(a, b, c, d, x[0], 3);
                    d = FF(d, a, b, c, x[1], 7);
                    c = FF(c, d, a, b, x[2], 11);
                    b = FF(b, c, d, a, x[3], 19);
                    a = FF(a, b, c, d, x[4], 3);
                    d = FF(d, a, b, c, x[5], 7);
                    c = FF(c, d, a, b, x[6], 11);
                    b = FF(b, c, d, a, x[7], 19);
                    a = FF(a, b, c, d, x[8], 3);
                    d = FF(d, a, b, c, x[9], 7);
                    c = FF(c, d, a, b, x[10], 11);
                    b = FF(b, c, d, a, x[11], 19);
                    a = FF(a, b, c, d, x[12], 3);
                    d = FF(d, a, b, c, x[13], 7);
                    c = FF(c, d, a, b, x[14], 11);
                    b = FF(b, c, d, a, x[15], 19);

                    a = GG(a, b, c, d, x[0], 3);
                    d = GG(d, a, b, c, x[4], 5);
                    c = GG(c, d, a, b, x[8], 9);
                    b = GG(b, c, d, a, x[12], 13);
                    a = GG(a, b, c, d, x[1], 3);
                    d = GG(d, a, b, c, x[5], 5);
                    c = GG(c, d, a, b, x[9], 9);
                    b = GG(b, c, d, a, x[13], 13);
                    a = GG(a, b, c, d, x[2], 3);
                    d = GG(d, a, b, c, x[6], 5);
                    c = GG(c, d, a, b, x[10], 9);
                    b = GG(b, c, d, a, x[14], 13);
                    a = GG(a, b, c, d, x[3], 3);
                    d = GG(d, a, b, c, x[7], 5);
                    c = GG(c, d, a, b, x[11], 9);
                    b = GG(b, c, d, a, x[15], 13);

                    a = HH(a, b, c, d, x[0], 3);
                    d = HH(d, a, b, c, x[8], 9);
                    c = HH(c, d, a, b, x[4], 11);
                    b = HH(b, c, d, a, x[12], 15);
                    a = HH(a, b, c, d, x[2], 3);
                    d = HH(d, a, b, c, x[10], 9);
                    c = HH(c, d, a, b, x[6], 11);
                    b = HH(b, c, d, a, x[14], 15);
                    a = HH(a, b, c, d, x[1], 3);
                    d = HH(d, a, b, c, x[9], 9);
                    c = HH(c, d, a, b, x[5], 11);
                    b = HH(b, c, d, a, x[13], 15);
                    a = HH(a, b, c, d, x[3], 3);
                    d = HH(d, a, b, c, x[11], 9);
                    c = HH(c, d, a, b, x[7], 11);
                    b = HH(b, c, d, a, x[15], 15);

                    a += aa;
                    b += bb;
                    c += cc;
                    d += dd;
                }
            }

            private static uint F(uint x, uint y, uint z)
            {
                return (x & y) | (~x & z);
            }

            private static uint G(uint x, uint y, uint z)
            {
                return (x & y) | (x & z) | (y & z);
            }

            private static uint H(uint x, uint y, uint z)
            {
                return x ^ y ^ z;
            }

            private static uint RotateLeft(uint value, int count)
            {
                return (value << count) | (value >> (32 - count));
            }

            private static uint FF(
                uint a, uint b, uint c, uint d, uint x, int s)
            {
                return RotateLeft(unchecked(a + F(b, c, d) + x), s);
            }

            private static uint GG(
                uint a, uint b, uint c, uint d, uint x, int s)
            {
                return RotateLeft(
                    unchecked(a + G(b, c, d) + x + 0x5a827999U), s);
            }

            private static uint HH(
                uint a, uint b, uint c, uint d, uint x, int s)
            {
                return RotateLeft(
                    unchecked(a + H(b, c, d) + x + 0x6ed9eba1U), s);
            }

            private static void WriteUInt32(
                byte[] value, int offset, uint number)
            {
                value[offset] = (byte)number;
                value[offset + 1] = (byte)(number >> 8);
                value[offset + 2] = (byte)(number >> 16);
                value[offset + 3] = (byte)(number >> 24);
            }
        }
    }
}
'@
}

function Get-I05FullPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Label path is required."
    }
    return [IO.Path]::GetFullPath($Path)
}

function Assert-I05PinnedSeed {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Pinned RC2 ffmpeg seed is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -ne $expected.seed_bytes) {
        throw "Pinned RC2 ffmpeg byte length mismatch: $($item.Length)"
    }
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($hash -ne $expected.seed_sha256) {
        throw "Pinned RC2 ffmpeg SHA-256 mismatch: $hash"
    }
    return [pscustomobject]@{
        path = $item.FullName
        bytes = [Int64]$item.Length
        sha256 = $hash.ToLowerInvariant()
    }
}

function Get-I05NtfsVolume {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path
    if ($item.PSProvider.Name -ne 'FileSystem') {
        throw 'The fixture path must use the Windows file-system provider.'
    }
    $root = [IO.Path]::GetPathRoot($item.FullName)
    if ($root.StartsWith('\\', [StringComparison]::Ordinal)) {
        throw 'UNC fixture paths are rejected because NTFS and free space cannot be attested locally.'
    }
    $volumes = @(Get-Volume -FilePath $item.FullName -ErrorAction Stop)
    if ($volumes.Count -ne 1) {
        throw "Expected one local volume for fixture path; found $($volumes.Count)."
    }
    $volume = $volumes[0]
    if (-not ([string]$volume.FileSystem).Equals(
            'NTFS', [StringComparison]::OrdinalIgnoreCase)) {
        throw "The canonical 4 GiB fixture requires NTFS; found '$($volume.FileSystem)'."
    }
    return $volume
}

function Write-I05Report {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [AllowEmptyString()][string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }
    $fullPath = Get-I05FullPath -Path $Path -Label 'Report'
    if (Test-Path -LiteralPath $fullPath) {
        throw "Refusing to overwrite an existing report: $fullPath"
    }
    $parent = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "Report parent directory does not exist: $parent"
    }
    $temporary = Join-Path $parent (
        '.' + (Split-Path -Leaf $fullPath) + '.' +
        [Guid]::NewGuid().ToString('N') + '.partial')
    try {
        [IO.File]::WriteAllText(
            $temporary,
            ($Value | ConvertTo-Json -Depth 8),
            (New-Object Text.UTF8Encoding($false)))
        [IO.File]::Move($temporary, $fullPath)
    } finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Convert-I05HexToBytes {
    param([Parameter(Mandatory = $true)][string]$Hex)

    if ($Hex.Length % 2 -ne 0 -or $Hex -notmatch '^[0-9a-fA-F]*$') {
        throw 'Self-test received malformed hexadecimal text.'
    }
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; ++$index) {
        $bytes[$index] = [Convert]::ToByte(
            $Hex.Substring($index * 2, 2), 16)
    }
    return $bytes
}

function Invoke-I05FixtureSelfTest {
    Initialize-I05FixtureHashType

    $vectors = @(
        @('', '31D6CFE0D16AE931B73C59D7E0C089C0'),
        @('a', 'BDE52CB31DE33E46245E05FBDBD6FB24'),
        @('abc', 'A448017AAF21D8525FC10AE87AA6729D'),
        @('message digest', 'D9130A8164549FE818874806E1C7014B')
    )
    foreach ($vector in $vectors) {
        $bytes = [Text.Encoding]::ASCII.GetBytes([string]$vector[0])
        $actual = [EseV91Lab.CanonicalFixture]::Md4Hex($bytes)
        if ($actual -ne [string]$vector[1]) {
            throw "MD4 self-test failed for '$($vector[0])': $actual"
        }
    }

    $testRoot = Join-Path ([IO.Path]::GetTempPath()) (
        'ese-v91-i05-fixture-selftest-' + [Guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $testRoot
    try {
        $seed = Join-Path $testRoot 'seed.bin'
        $target = Join-Path $testRoot 'target.bin'
        $seedBytes = [Text.Encoding]::ASCII.GetBytes('abcde')
        [IO.File]::WriteAllBytes($seed, $seedBytes)
        $created = [EseV91Lab.CanonicalFixture]::CreateRepeatedFile(
            $seed, $target, 3, 2)
        $expectedBytes = [Text.Encoding]::ASCII.GetBytes(
            'abcdeabcdeabcdeab')
        $actualBytes = [IO.File]::ReadAllBytes($target)
        if ([BitConverter]::ToString($expectedBytes) -ne
            [BitConverter]::ToString($actualBytes)) {
            throw 'Streaming recipe self-test produced unexpected bytes.'
        }
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $expectedSha = ([BitConverter]::ToString(
                $sha.ComputeHash($expectedBytes))).Replace('-', '')
        } finally {
            $sha.Dispose()
        }
        $expectedEd2k =
            [EseV91Lab.CanonicalFixture]::Md4Hex($expectedBytes)
        if ($created.Bytes -ne $expectedBytes.Length -or
            $created.Sha256 -ne $expectedSha -or
            $created.Ed2k -ne $expectedEd2k) {
            throw 'Streaming recipe self-test returned inconsistent hashes.'
        }
        $verified = [EseV91Lab.CanonicalFixture]::HashFile($target)
        if ($verified.Bytes -ne $created.Bytes -or
            $verified.Sha256 -ne $created.Sha256 -or
            $verified.Ed2k -ne $created.Ed2k) {
            throw 'Create and verify self-test results disagree.'
        }

        # Exercise eMule's exact PARTSIZE boundary. At exactly 9,728,000
        # bytes, ED2K hashes the full part plus a trailing empty part, then
        # hashes the two 16-byte MD4 digests.
        $boundaryPath = Join-Path $testRoot 'ed2k-boundary.bin'
        $boundaryBytes = New-Object byte[] 9728000
        [IO.File]::WriteAllBytes($boundaryPath, $boundaryBytes)
        $partHash = [EseV91Lab.CanonicalFixture]::Md4Hex($boundaryBytes)
        $emptyHash = '31D6CFE0D16AE931B73C59D7E0C089C0'
        $rootInput = New-Object byte[] 32
        $partHashBytes = Convert-I05HexToBytes -Hex $partHash
        $emptyHashBytes = Convert-I05HexToBytes -Hex $emptyHash
        [Array]::Copy($partHashBytes, 0, $rootInput, 0, 16)
        [Array]::Copy($emptyHashBytes, 0, $rootInput, 16, 16)
        $expectedBoundaryEd2k =
            [EseV91Lab.CanonicalFixture]::Md4Hex($rootInput)
        $boundaryResult =
            [EseV91Lab.CanonicalFixture]::HashFile($boundaryPath)
        if ($boundaryResult.Bytes -ne 9728000 -or
            $boundaryResult.Ed2k -ne $expectedBoundaryEd2k) {
            throw (
                'ED2K multipart boundary self-test failed: ' +
                "$($boundaryResult.Ed2k)")
        }
    } finally {
        if (Test-Path -LiteralPath $testRoot) {
            Remove-Item -LiteralPath $testRoot -Recurse -Force `
                -ErrorAction SilentlyContinue
        }
    }

    return [ordered]@{
        schema = 'ese.v91.i05-canonical-fixture-report/v1'
        case_id = 'V91-I05'
        mode = 'SelfTest'
        status = 'PASS'
        tested_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        md4_vectors = $vectors.Count
        streaming_recipe_test_bytes = 17
        ed2k_boundary_test_bytes = 9728000
        canonical_fixture_created = $false
    }
}

Initialize-I05FixtureHashType

if ($Mode -eq 'SelfTest') {
    $selfTest = Invoke-I05FixtureSelfTest
    Write-I05Report -Value $selfTest -Path $ReportPath
    [pscustomobject]$selfTest
    return
}

$seedFullPath = Get-I05FullPath -Path $SeedPath -Label 'Seed'
$fixtureFullPath = Get-I05FullPath -Path $FixturePath -Label 'Fixture'
if ($seedFullPath.Equals(
        $fixtureFullPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'SeedPath and FixturePath must be different files.'
}
if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
    $reportFullPath = Get-I05FullPath -Path $ReportPath -Label 'Report'
    if ($reportFullPath.Equals(
            $seedFullPath, [StringComparison]::OrdinalIgnoreCase) -or
        $reportFullPath.Equals(
            $fixtureFullPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'ReportPath must differ from the seed and fixture paths.'
    }
}

$seedInfo = Assert-I05PinnedSeed -Path $seedFullPath
$result = $null
$volume = $null

if ($Mode -eq 'Create') {
    if (Test-Path -LiteralPath $fixtureFullPath) {
        throw "Refusing to overwrite an existing fixture: $fixtureFullPath"
    }
    $fixtureParent = Split-Path -Parent $fixtureFullPath
    if (-not (Test-Path -LiteralPath $fixtureParent -PathType Container)) {
        throw "Fixture parent directory does not exist: $fixtureParent"
    }
    $volume = Get-I05NtfsVolume -Path $fixtureParent
    [Int64]$requiredFree =
        $expected.fixture_bytes + $MinimumFreeAfterBytes
    if ([Int64]$volume.SizeRemaining -lt $requiredFree) {
        throw (
            "Insufficient free space. Need at least $requiredFree bytes; " +
            "volume reports $($volume.SizeRemaining).")
    }

    $temporary = Join-Path $fixtureParent (
        '.' + (Split-Path -Leaf $fixtureFullPath) + '.' +
        [Guid]::NewGuid().ToString('N') + '.partial')
    try {
        $result = [EseV91Lab.CanonicalFixture]::CreateRepeatedFile(
            $seedFullPath,
            $temporary,
            $expected.full_repetitions,
            $expected.trailing_bytes)
        if ($result.Bytes -ne $expected.fixture_bytes -or
            $result.Sha256 -ne $expected.fixture_sha256 -or
            $result.Ed2k -ne $expected.fixture_ed2k) {
            throw (
                'Generated fixture failed canonical identity checks: ' +
                "bytes=$($result.Bytes), sha256=$($result.Sha256), " +
                "ed2k=$($result.Ed2k)")
        }
        [IO.File]::Move($temporary, $fixtureFullPath)
    } finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force `
                -ErrorAction SilentlyContinue
        }
    }
} else {
    if (-not (Test-Path -LiteralPath $fixtureFullPath -PathType Leaf)) {
        throw "Canonical fixture is missing: $fixtureFullPath"
    }
    $fixtureItem = Get-Item -LiteralPath $fixtureFullPath
    if ($fixtureItem.Length -ne $expected.fixture_bytes) {
        throw "Canonical fixture byte length mismatch: $($fixtureItem.Length)"
    }
    $volume = Get-I05NtfsVolume -Path $fixtureFullPath
    $result = [EseV91Lab.CanonicalFixture]::HashFile($fixtureFullPath)
    if ($result.Sha256 -ne $expected.fixture_sha256 -or
        $result.Ed2k -ne $expected.fixture_ed2k) {
        throw (
            'Fixture identity mismatch: ' +
            "sha256=$($result.Sha256), ed2k=$($result.Ed2k)")
    }
}

# Refresh the storage snapshot after creation so the report does not label
# the pre-allocation free-space value as the post-run value.
$volume = Get-I05NtfsVolume -Path $fixtureFullPath

$report = [ordered]@{
    schema = 'ese.v91.i05-canonical-fixture-report/v1'
    case_id = 'V91-I05'
    mode = $Mode
    status = if ($Mode -eq 'Create') { 'CREATED' } else { 'VERIFIED' }
    completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    seed = [ordered]@{
        name = $expected.seed_name
        path = $seedInfo.path
        bytes = $seedInfo.bytes
        sha256 = $seedInfo.sha256
    }
    recipe = [ordered]@{
        full_repetitions = $expected.full_repetitions
        trailing_bytes = $expected.trailing_bytes
        expected_bytes = $expected.fixture_bytes
    }
    fixture = [ordered]@{
        path = $fixtureFullPath
        bytes = [Int64]$result.Bytes
        sha256 = $result.Sha256.ToLowerInvariant()
        ed2k = $result.Ed2k
    }
    storage = [ordered]@{
        file_system = [string]$volume.FileSystem
        volume_path = [string]$volume.Path
        size_remaining_after = [Int64]$volume.SizeRemaining
        minimum_free_after_requested = $MinimumFreeAfterBytes
    }
}

Write-I05Report -Value $report -Path $ReportPath
[pscustomobject]$report
