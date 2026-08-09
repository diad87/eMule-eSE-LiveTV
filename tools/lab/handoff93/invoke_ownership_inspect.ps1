[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$stage = 'INPUT'
$inspectorHandle = $null
$journalHandle = $null

function Read-FixedField([string] $ExpectedName) {
    $line = [Console]::In.ReadLine()
    if ($null -eq $line -or -not $line.StartsWith("$ExpectedName=")) { throw 'invalid envelope' }
    return $line.Substring($ExpectedName.Length + 1)
}

function Assert-HexHash([string] $Value) {
    if ($Value -notmatch '^[0-9a-f]{64}$') { throw 'invalid hash' }
}

function Get-RegularNonReparsePath([string] $InputPath) {
    $full = [IO.Path]::GetFullPath($InputPath)
    if (-not [IO.Path]::IsPathRooted($full) -or $full.StartsWith('\\')) { throw 'non-local path rejected' }
    $root = [IO.Path]::GetPathRoot($full)
    $device = $root.TrimEnd('\')
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$device'"
    if ($null -eq $disk -or $disk.DriveType -ne 3) { throw 'fixed local volume required' }
    $relative = $full.Substring($root.Length)
    $cursor = $root
    foreach ($component in $relative.Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)) {
        $cursor = Join-Path $cursor $component
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse path rejected' }
    }
    $leaf = Get-Item -LiteralPath $full -Force
    if ($leaf.PSIsContainer -or ($leaf.Attributes -band [IO.FileAttributes]::Directory) -ne 0) { throw 'regular file required' }
    $resolved = (Resolve-Path -LiteralPath $full).Path
    if (-not [string]::Equals($resolved, $full, [StringComparison]::OrdinalIgnoreCase)) { throw 'path identity changed' }
    return $full
}

function Get-HashLower([string] $Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StreamHashLower([IO.FileStream] $Stream) {
    $Stream.Position = 0
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash($Stream) } finally { $sha.Dispose(); $Stream.Position = 0 }
    return ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

try {
    $inspectorInput = Read-FixedField 'inspector_path'
    $journalInput = Read-FixedField 'journal_path'
    $inspectorExpectedHash = Read-FixedField 'inspector_sha256'
    $callerExpectedHash = Read-FixedField 'caller_sha256'
    $journalExpectedHash = Read-FixedField 'journal_sha256'
    $generation = Read-FixedField 'generation'
    $tcpLocal = Read-FixedField 'tcp_local'
    $tcpExternal = Read-FixedField 'tcp_external'
    $udpLocal = Read-FixedField 'udp_local'
    $udpExternal = Read-FixedField 'udp_external'
    if ($null -ne [Console]::In.ReadLine()) { throw 'trailing input' }
    Assert-HexHash $inspectorExpectedHash
    Assert-HexHash $callerExpectedHash
    Assert-HexHash $journalExpectedHash

    $stage = 'IDENTITY'
    $inspector = Get-RegularNonReparsePath $inspectorInput
    $journal = Get-RegularNonReparsePath $journalInput
    $caller = Get-RegularNonReparsePath $PSCommandPath
    $leaf = [IO.Path]::GetFileName($journal)
    if ($leaf -ne 'natmap-ownership.dat') { throw 'invalid journal identity' }
    $inspectorHandle = [IO.File]::Open($inspector, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $journalHandle = [IO.File]::Open($journal, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    if ((Get-StreamHashLower $inspectorHandle) -ne $inspectorExpectedHash -or
        (Get-HashLower $caller) -ne $callerExpectedHash -or
        (Get-StreamHashLower $journalHandle) -ne $journalExpectedHash) { throw 'hash mismatch' }

    $payload = @(
        "generation=$generation", "tcp_local=$tcpLocal",
        "tcp_external=$tcpExternal", "udp_local=$udpLocal",
        "udp_external=$udpExternal", "journal_sha256=$journalExpectedHash"
    )
    $stage = 'INVOKE'
    # Revalidate immediately before launch. The native reader additionally
    # holds and revalidates one file handle across the complete decode.
    if ((Get-RegularNonReparsePath $inspector) -ne $inspector -or
        (Get-RegularNonReparsePath $journal) -ne $journal -or
        (Get-StreamHashLower $inspectorHandle) -ne $inspectorExpectedHash -or
        (Get-StreamHashLower $journalHandle) -ne $journalExpectedHash) { throw 'prelaunch identity changed' }
    if ($env:ESE_OWNERSHIP_TEST_HOOK -eq '1') {
        $ready = [Threading.EventWaitHandle]::OpenExisting($env:ESE_OWNERSHIP_READY_EVENT)
        $continue = [Threading.EventWaitHandle]::OpenExisting($env:ESE_OWNERSHIP_CONTINUE_EVENT)
        try {
            [void]$ready.Set()
            if (-not $continue.WaitOne(10000)) { throw 'test hook timeout' }
        } finally { $ready.Dispose(); $continue.Dispose() }
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $inspector
    $start.Arguments = '--expect-pair natmap-ownership.dat'
    $start.WorkingDirectory = [IO.Path]::GetDirectoryName($journal)
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    foreach ($line in $payload) { $process.StandardInput.WriteLine($line) }
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd().Trim()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    $stage = 'OUTPUT'
    if ((Get-RegularNonReparsePath $inspector) -ne $inspector -or
        (Get-RegularNonReparsePath $journal) -ne $journal -or
        (Get-RegularNonReparsePath $caller) -ne $caller -or
        (Get-StreamHashLower $inspectorHandle) -ne $inspectorExpectedHash -or
        (Get-HashLower $caller) -ne $callerExpectedHash -or
        (Get-StreamHashLower $journalHandle) -ne $journalExpectedHash) { throw 'postrun identity changed' }
    if ($stderr.Length -ne 0 -or $process.ExitCode -notin @(0,2,3,4,5,6,7)) { throw 'invalid child channel' }
    $allowed = @(
        'codec=PASS schema=PASS checksum=PASS count=PASS pair=PASS',
        'codec=PASS schema=PASS checksum=PASS count=PASS pair=FAIL',
        'codec=PASS schema=PASS checksum=PASS count=FAIL pair=FAIL',
        'codec=FAIL reason=INVALID_EXPECTATION', 'codec=FAIL reason=NOT_FOUND',
        'codec=FAIL reason=LENGTH', 'codec=FAIL reason=READ',
        'codec=FAIL reason=HASH',
        'codec=FAIL class=CHECKSUM_FAIL', 'codec=FAIL class=SCHEMA_FAIL',
        'codec=FAIL class=LENGTH_FAIL', 'codec=FAIL class=RECORD_FAIL',
        'codec=FAIL class=DECODE_FAIL'
    )
    if ($stdout -notin $allowed) { throw 'unrecognized child output' }
    $coherent = switch ($process.ExitCode) {
        0 { $stdout -eq $allowed[0] }
        2 { $stdout -eq 'codec=FAIL reason=INVALID_EXPECTATION' }
        3 { $stdout -eq 'codec=FAIL reason=NOT_FOUND' }
        4 { $stdout -eq 'codec=FAIL reason=LENGTH' }
        5 { $stdout -eq 'codec=FAIL reason=READ' }
        6 { $stdout.StartsWith('codec=FAIL class=') -or $stdout -eq 'codec=FAIL reason=HASH' }
        7 { $stdout -eq $allowed[1] -or $stdout -eq $allowed[2] }
        default { $false }
    }
    if (-not $coherent) { throw 'incoherent child result' }
    [Console]::Out.WriteLine($stdout)
    exit $process.ExitCode
} catch {
    [Console]::Out.WriteLine("codec=FAIL reason=CALLER stage=$stage")
    exit 2
} finally {
    if ($journalHandle -ne $null) { $journalHandle.Dispose() }
    if ($inspectorHandle -ne $null) { $inspectorHandle.Dispose() }
}
