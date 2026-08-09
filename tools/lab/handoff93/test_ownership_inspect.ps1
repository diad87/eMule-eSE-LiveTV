[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Inspector,
    [Parameter(Mandatory = $true)][string] $Fixture,
    [Parameter(Mandatory = $true)][string] $Caller
)

$ErrorActionPreference = 'Stop'
$inspectorPath = (Resolve-Path -LiteralPath $Inspector).Path
$fixturePath = (Resolve-Path -LiteralPath $Fixture).Path
$callerPath = (Resolve-Path -LiteralPath $Caller).Path
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('ese-ownership-test-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($scratch) | Out-Null

function Invoke-SafeCaller([string[]] $lines, [bool] $exerciseLocks = $false) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = 'powershell.exe'
    $start.Arguments = '-NoProfile -ExecutionPolicy Bypass -File invoke_ownership_inspect.ps1'
    $start.WorkingDirectory = [IO.Path]::GetDirectoryName($callerPath)
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    if ($exerciseLocks) {
        $suffix = [guid]::NewGuid().ToString('N')
        $ready = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, "Local\ese-own-ready-$suffix")
        $continue = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, "Local\ese-own-continue-$suffix")
        $start.EnvironmentVariables['ESE_OWNERSHIP_TEST_HOOK'] = '1'
        $start.EnvironmentVariables['ESE_OWNERSHIP_READY_EVENT'] = "Local\ese-own-ready-$suffix"
        $start.EnvironmentVariables['ESE_OWNERSHIP_CONTINUE_EVENT'] = "Local\ese-own-continue-$suffix"
    }
    $process = [Diagnostics.Process]::Start($start)
    $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($process.Id)").CommandLine
    if ($commandLine -match [regex]::Escape($scratch) -or
        $commandLine -match '41001|42001|41002|42002' -or
        $commandLine -match [regex]::Escape($callerPath)) { throw 'caller command line leak' }
    foreach ($line in $lines) { $process.StandardInput.WriteLine($line) }
    $process.StandardInput.Close()
    if ($exerciseLocks) {
        if (-not $ready.WaitOne(10000)) { throw 'lock hook timeout' }
        $journalPath = $lines[1].Substring('journal_path='.Length)
        $inspectorInputPath = $lines[0].Substring('inspector_path='.Length)
        $journalMoved = $false
        $inspectorMoved = $false
        try { Move-Item -LiteralPath $journalPath -Destination ($journalPath + '.swap') -ErrorAction Stop; $journalMoved = $true } catch {}
        try { Move-Item -LiteralPath $inspectorInputPath -Destination ($inspectorInputPath + '.swap') -ErrorAction Stop; $inspectorMoved = $true } catch {}
        if ($journalMoved) { Move-Item -LiteralPath ($journalPath + '.swap') -Destination $journalPath -Force }
        if ($inspectorMoved) { Move-Item -LiteralPath ($inspectorInputPath + '.swap') -Destination $inspectorInputPath -Force }
        [void]$continue.Set()
        $ready.Dispose(); $continue.Dispose()
        if ($journalMoved -or $inspectorMoved) { throw 'sharing lock failed' }
    }
    $stdout = $process.StandardOutput.ReadToEnd().Trim()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    return [pscustomobject]@{ ExitCode=$process.ExitCode; Stdout=$stdout; Stderr=$stderr }
}

function Invoke-Case([string] $variant, [string[]] $inputLines, [int] $expectedExit, [string] $expectedOutput) {
    Push-Location -LiteralPath $scratch
    try {
        & $fixturePath 'natmap-ownership.dat' $variant
        if ($LASTEXITCODE -ne 0) { throw 'fixture failed' }
        $fixtureHash = (Get-FileHash -LiteralPath 'natmap-ownership.dat' -Algorithm SHA256).Hash.ToLowerInvariant()
        $actual = (@($inputLines) + "journal_sha256=$fixtureHash") | & $inspectorPath --expect-pair 'natmap-ownership.dat'
        $exitCode = $LASTEXITCODE
    } finally { Pop-Location }
    if ($exitCode -ne $expectedExit -or ($actual -join "`n") -ne $expectedOutput) { throw "case failed: $variant" }
    if (($actual -join "`n") -match '4100|4200|192\.0\.2|123456|abcdef|tailscale|ese-owned') { throw 'privacy leak' }
}

$valid = @('generation=9','tcp_local=41001','tcp_external=42001','udp_local=41002','udp_external=42002')
try {
    Invoke-Case 'valid' $valid 0 'codec=PASS schema=PASS checksum=PASS count=PASS pair=PASS'
    Invoke-Case 'valid' @('generation=9','tcp_local=41001','tcp_external=42001','udp_local=41002','udp_external=42003') 7 'codec=PASS schema=PASS checksum=PASS count=PASS pair=FAIL'
    Invoke-Case 'crc' $valid 6 'codec=FAIL class=CHECKSUM_FAIL'
    Invoke-Case 'schema' $valid 6 'codec=FAIL class=SCHEMA_FAIL'
    Invoke-Case 'truncated' $valid 6 'codec=FAIL class=LENGTH_FAIL'
    Invoke-Case 'oversize' $valid 4 'codec=FAIL reason=LENGTH'
    Push-Location -LiteralPath $scratch
    try {
        & $fixturePath 'natmap-ownership.dat' 'valid'
        if ($LASTEXITCODE -ne 0) { throw 'direct fixture failed' }
        $currentHash = (Get-FileHash -LiteralPath 'natmap-ownership.dat' -Algorithm SHA256).Hash.ToLowerInvariant()
        $invalid = @('generation=+9','tcp_local=41001','tcp_external=42001','udp_local=41002','udp_external=42002',"journal_sha256=$currentHash") | & $inspectorPath --expect-pair 'natmap-ownership.dat'
        $invalidExit = $LASTEXITCODE
        $hashMismatch = (@($valid) + ('journal_sha256=' + ('0' * 64))) | & $inspectorPath --expect-pair 'natmap-ownership.dat'
        $hashMismatchExit = $LASTEXITCODE
        $missing = (@($valid) + "journal_sha256=$currentHash") | & $inspectorPath --expect-pair 'missing.dat'
        $missingExit = $LASTEXITCODE
        [IO.Directory]::CreateDirectory((Join-Path $scratch 'unreadable.dat')) | Out-Null
        $unreadable = (@($valid) + "journal_sha256=$currentHash") | & $inspectorPath --expect-pair 'unreadable.dat'
        $unreadableExit = $LASTEXITCODE
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $badArg = & $inspectorPath --expect-pair '..\natmap-ownership.dat' 2>$null
        $badArgExit = $LASTEXITCODE
        $ErrorActionPreference = $savedPreference
    } finally { Pop-Location }
    if ($invalidExit -ne 2 -or ($invalid -join '') -ne 'codec=FAIL reason=INVALID_EXPECTATION') { throw 'invalid input case failed' }
    if ($hashMismatchExit -ne 6 -or ($hashMismatch -join '') -ne 'codec=FAIL reason=HASH') { throw "journal hash case failed exit=$hashMismatchExit output=$($hashMismatch -join '')" }
    if ($missingExit -ne 3 -or ($missing -join '') -ne 'codec=FAIL reason=NOT_FOUND') { throw 'missing case failed' }
    if ($unreadableExit -ne 5 -or ($unreadable -join '') -ne 'codec=FAIL reason=READ') { throw 'read failure case failed' }
    if ($badArgExit -ne 2 -or ($badArg -join '') -ne '') { throw 'unsafe argv case failed' }
    $journal = Join-Path $scratch 'natmap-ownership.dat'
    Push-Location -LiteralPath $scratch
    try {
        & $fixturePath 'natmap-ownership.dat' 'valid'
        if ($LASTEXITCODE -ne 0) { throw 'caller fixture failed' }
    } finally { Pop-Location }
    $inspectorHash = (Get-FileHash -LiteralPath $inspectorPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $callerHash = (Get-FileHash -LiteralPath $callerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $journalHash = (Get-FileHash -LiteralPath $journal -Algorithm SHA256).Hash.ToLowerInvariant()
    $callerInput = @(
        "inspector_path=$inspectorPath", "journal_path=$journal",
        "inspector_sha256=$inspectorHash", "caller_sha256=$callerHash",
        "journal_sha256=$journalHash",
        'generation=9', 'tcp_local=41001', 'tcp_external=42001',
        'udp_local=41002', 'udp_external=42002'
    )
    $callerResult = Invoke-SafeCaller $callerInput $true
    if ($callerResult.ExitCode -ne 0 -or $callerResult.Stdout -ne 'codec=PASS schema=PASS checksum=PASS count=PASS pair=PASS' -or $callerResult.Stderr.Length -ne 0) { throw "safe caller case failed exit=$($callerResult.ExitCode) output=$($callerResult.Stdout)" }

    # A path swap is caught by the expected hash even when the replacement is
    # another regular file. A directory junction is rejected component-wise.
    $swapped = $callerInput.Clone()
    $swapped[4] = ('journal_sha256=' + ('0' * 64))
    $swapResult = Invoke-SafeCaller $swapped
    if ($swapResult.ExitCode -ne 2 -or $swapResult.Stdout -ne 'codec=FAIL reason=CALLER stage=IDENTITY') { throw 'swap test failed' }
    $junction = $scratch + '-junction'
    cmd /c "mklink /J `"$junction`" `"$scratch`"" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'junction fixture failed' }
    $junctionInput = $callerInput.Clone()
    $junctionInput[1] = "journal_path=$(Join-Path $junction 'natmap-ownership.dat')"
    $junctionResult = Invoke-SafeCaller $junctionInput
    if ($junctionResult.ExitCode -ne 2 -or $junctionResult.Stdout -ne 'codec=FAIL reason=CALLER stage=IDENTITY') { throw 'junction test failed' }
    [IO.Directory]::Delete($junction)
    Write-Output 'ownership inspector binary campaign: PASS'
} finally {
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
}
