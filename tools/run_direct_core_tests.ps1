[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('x64','Win32')][string]$Architecture,
    [Parameter(Mandatory=$true)][string]$OutputRoot
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$output = [IO.Path]::GetFullPath($OutputRoot)
if (Test-Path -LiteralPath $output) { throw 'Use a new output directory; previous evidence must be preserved.' }
New-Item -ItemType Directory -Path $output | Out-Null
$vc = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build'
$setup = Join-Path $vc $(if ($Architecture -eq 'x64') { 'vcvars64.bat' } else { 'vcvars32.bat' })
if (-not (Test-Path -LiteralPath $setup)) { throw 'Compiler environment not found.' }
$cases = @(
    @{ Name='direct_attempt'; Sources=@('direct_attempt') },
    @{ Name='direct_session'; Sources=@('direct_session') },
    @{ Name='direct_coordinator'; Sources=@('direct_coordinator','direct_session') },
    @{ Name='direct_event_queue'; Sources=@('direct_event_queue','direct_coordinator','direct_session') },
    @{ Name='direct_transport'; Sources=@('direct_transport') },
    @{ Name='part_owner_domain'; Sources=@() },
    @{ Name='direct_diagnostics'; Sources=@() }
)
$inputs = @(Get-ChildItem -LiteralPath (Join-Path $repo 'libreach/include/reach') -File)
foreach ($case in $cases) {
    $inputs += Get-Item -LiteralPath (Join-Path $repo "libreach/tests/test_$($case.Name).cpp")
    foreach ($source in $case.Sources) { $inputs += Get-Item -LiteralPath (Join-Path $repo "libreach/src/$source.cpp") }
}
$hashes = @($inputs | Sort-Object FullName -Unique | ForEach-Object {
    @{ path=$_.FullName; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
})
$results = @()
$verdict = 'FAIL'
try {
    foreach ($case in $cases) {
        $name = "test_$($case.Name)"
        $exe = Join-Path $output "$name.exe"
        $compileLog = Join-Path $output "$name-build.log"
        $runLog = Join-Path $output "$name-run.log"
        $sources = @((Join-Path $repo "libreach/tests/$name.cpp"))
        foreach ($source in $case.Sources) { $sources += Join-Path $repo "libreach/src/$source.cpp" }
        $quotedSources = ($sources | ForEach-Object { '"' + $_ + '"' }) -join ' '
        $command = 'call "' + $setup + '" >nul 2>&1 && cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /I"' + (Join-Path $repo 'libreach/include') + '" /Fe"' + $exe + '" ' + $quotedSources
        Push-Location $output
        try { & cmd /d /c $command *> $compileLog; $buildExit = $LASTEXITCODE }
        finally { Pop-Location }
        if ($buildExit -ne 0) { throw "$name compile failed: $buildExit" }
        & $exe *> $runLog
        $runExit = $LASTEXITCODE
        $results += @{ name=$name; exit_code=$runExit; exe_sha256=(Get-FileHash $exe).Hash; log_sha256=(Get-FileHash $runLog).Hash }
        if ($runExit -ne 0) { throw "$name failed: $runExit" }
        Write-Host "$Architecture $name PASS"
    }
    foreach ($input in $hashes) {
        if ((Get-FileHash -LiteralPath $input.path).Hash -ne $input.sha256) { throw "Input changed during execution: $($input.path)" }
    }
    $verdict = 'PASS'
} finally {
    @{ schema='ese.v93.direct-core/1'; architecture=$Architecture; verdict=$verdict; terminal=$true; inputs=$hashes; tests=$results } |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $output 'core-evidence.json') -Encoding UTF8
}
Write-Host "Direct Core $Architecture PASS"
