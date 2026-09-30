<#
.SYNOPSIS
    Rehearse existing pure baseline tests in an isolated source copy.
.DESCRIPTION
    PREPARATION ONLY. Does not evaluate G92-93-DEV, approve an ADR, execute
    WP93-0, launch eMule, access a router, or exercise a physical network.
    Retains inputs, build outputs, logs and SHA-256 provenance in a new folder.
    Never deletes or overwrites an existing run. Crypto++ is a recorded,
    prebuilt dependency, not a fresh build of that library.
#>
[CmdletBinding()]
param(
    [string]$SourceRoot = '',
    [Parameter(Mandatory = $true)][string]$RunDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$runnerHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
if (-not $SourceRoot) { $SourceRoot = Split-Path -Parent $PSScriptRoot }
$source = (Resolve-Path -LiteralPath $SourceRoot).Path
$run = [IO.Path]::GetFullPath($RunDirectory)
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
# Paths are interpolated into a cmd invocation; reject shell metacharacters.
foreach ($value in @($source, $run, $vcvars)) {
    if ($value -match '[%!&|<>^"\r\n]') {
        throw 'Unsupported shell metacharacter in path.'
    }
}
if (Test-Path -LiteralPath $run) { throw 'RunDirectory must not already exist.' }
if (-not (Test-Path -LiteralPath $vcvars -PathType Leaf)) { throw 'MSVC toolchain is unavailable.' }
if ($run.StartsWith($source.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'RunDirectory must be outside SourceRoot.'
}

$inputs = New-Object 'System.Collections.Generic.List[string]'
foreach ($lib in @('libreach', 'libnatmap')) {
    $inputs.Add("$lib/make.bat")
    foreach ($part in @('include', 'src', 'tests')) {
        foreach ($file in (Get-ChildItem -LiteralPath (Join-Path $source "$lib/$part") -File -Recurse)) {
            $inputs.Add($file.FullName.Substring($source.Length + 1).Replace('\', '/'))
        }
    }
}
foreach ($relative in @('srchybrid/HolePunchCookieCore.h',
        'srchybrid/tests/test_holepunch_cookie.cpp',
        'cryptopp/x64/Output/Release/cryptlib.lib',
        'tools/lab/common.ps1', 'tools/lab/handoff93/validate_reach_status.ps1')) {
    $inputs.Add($relative)
}
foreach ($file in (Get-ChildItem -LiteralPath (Join-Path $source 'cryptopp') -Filter '*.h' -File)) {
    $inputs.Add('cryptopp/' + $file.Name)
}
$goldenFiles = @(Get-ChildItem -LiteralPath (Join-Path $source 'tools/lab/handoff93/goldens') -Filter '*.json' -File)
$expectedGoldens = @('candidate.json', 'empty.json', 'expired.json', 'stale.json', 'verified.json')
if ($goldenFiles.Count -ne 5 -or
        @(Compare-Object $expectedGoldens @($goldenFiles.Name)).Count -ne 0) {
    throw 'Exactly the five reviewed reach-status goldens are required.'
}
foreach ($file in $goldenFiles) {
    $inputs.Add('tools/lab/handoff93/goldens/' + $file.Name)
}

$hashes = @($inputs | Sort-Object -Unique | ForEach-Object {
    $path = Join-Path $source $_
    [ordered]@{ path = $_; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
})
$commit = (& git -C $source rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify source commit.' }
$status = @(& git -C $source status --porcelain)
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify source status.' }
$copy = Join-Path $run 'source-copy'
$null = New-Item -ItemType Directory -Path $copy
$runnerCopy = Join-Path $run 'runner.ps1'
Copy-Item -LiteralPath $PSCommandPath -Destination $runnerCopy
if ((Get-FileHash -LiteralPath $runnerCopy).Hash -ne $runnerHash) {
    throw 'Runner changed while copying.'
}
foreach ($item in $hashes) {
    $target = Join-Path $copy $item.path
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force
    Copy-Item -LiteralPath (Join-Path $source $item.path) -Destination $target
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $item.sha256) {
        throw "Source changed while copying: $($item.path)"
    }
}
$null = New-Item -ItemType Directory -Path (Join-Path $copy 'srchybrid/tests/build')
$localTemp = Join-Path $run 'temp'
$null = New-Item -ItemType Directory -Path $localTemp
$results = New-Object System.Collections.ArrayList

function Invoke-RecordedProcess {
    param([string]$Name, [string]$Executable, [string]$Arguments, [string]$WorkingDirectory)
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $start.Arguments = $Arguments
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    # Inherited compiler overrides could redirect outputs outside the copy.
    foreach ($nameToRemove in @('CL', '_CL_', 'LINK', '_LINK_')) {
        $start.EnvironmentVariables.Remove($nameToRemove)
    }
    $start.EnvironmentVariables['TEMP'] = $localTemp
    $start.EnvironmentVariables['TMP'] = $localTemp
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    try {
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $output = $stdout.Result + $stderr.Result
        $log = Join-Path $run ($Name + '.log')
        [IO.File]::WriteAllText($log, $output, [Text.Encoding]::UTF8)
        $null = $results.Add([ordered]@{
            name = $Name; executable = $Executable; arguments = $Arguments
            working_directory = $WorkingDirectory; exit_code = $process.ExitCode
            log = $Name + '.log'; log_sha256 = (Get-FileHash -LiteralPath $log).Hash
        })
        Write-Host "$Name exit=$($process.ExitCode)"
        Write-Host $output
    } finally { $process.Dispose() }
}

foreach ($lib in @('libreach', 'libnatmap')) {
    Invoke-RecordedProcess -Name $lib -Executable $env:ComSpec -Arguments '/d /c make.bat' `
        -WorkingDirectory (Join-Path $copy $lib)
}
$cookieCommand = 'call "{0}" >nul 2>&1 && cl /EHsc /O2 /W4 /WX /std:c++17 /I.. /Fetests\build\test_holepunch_cookie.exe tests\test_holepunch_cookie.cpp "..\cryptopp\x64\Output\Release\cryptlib.lib" && tests\build\test_holepunch_cookie.exe' -f $vcvars
Invoke-RecordedProcess -Name 'cookie' -Executable $env:ComSpec -Arguments ('/d /c ' + $cookieCommand) `
    -WorkingDirectory (Join-Path $copy 'srchybrid')
$goldensArguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Goldens -OutFile "{1}"' -f `
    (Join-Path $copy 'tools/lab/handoff93/validate_reach_status.ps1'), (Join-Path $run 'goldens.json')
Invoke-RecordedProcess -Name 'reach-status-goldens' -Executable (Join-Path $PSHOME 'powershell.exe') `
    -Arguments $goldensArguments -WorkingDirectory $copy

$changed = @($hashes | Where-Object {
    $path = Join-Path $source $_.path
    (-not (Test-Path -LiteralPath $path -PathType Leaf)) -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $_.sha256
} | ForEach-Object { $_.path })
$failed = @($results | Where-Object { $_.exit_code -ne 0 })
$copyChanged = @($hashes | Where-Object {
    $path = Join-Path $copy $_.path
    (-not (Test-Path -LiteralPath $path -PathType Leaf)) -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $_.sha256
} | ForEach-Object { $_.path })
$verdict = 'PASS'
$runnerChanged = (Get-FileHash -LiteralPath $PSCommandPath).Hash -ne $runnerHash
if ($failed.Count -gt 0 -or $changed.Count -gt 0 -or $copyChanged.Count -gt 0 -or $runnerChanged) {
    $verdict = 'FAIL'
}
$manifest = [ordered]@{
    schema = 'ese.v93.preparation-baseline/v1'
    evidence_class = 'PREPARATION_ONLY'; gate_evaluated = $false
    functional_card_completed = $false; physical_tests_run = $false
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    source_root = $source; source_commit = $commit; source_dirty = ($status.Count -gt 0)
    source_copy = $copy; inputs = $hashes; changed_inputs = $changed; changed_copy_inputs = $copyChanged
    runner_sha256 = $runnerHash; runner_copy = 'runner.ps1'; runner_changed = $runnerChanged
    powershell_version = $PSVersionTable.PSVersion.ToString()
    vcvars = $vcvars; vcvars_sha256 = (Get-FileHash -LiteralPath $vcvars).Hash
    child_environment_removed = @('CL', '_CL_', 'LINK', '_LINK_'); child_temp = $localTemp
    crypto_dependency = 'PREBUILT_NOT_REBUILT'; lanes = @($results); rehearsal_verdict = $verdict
}
$manifestPath = Join-Path $run 'manifest.json'
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 10), [Text.Encoding]::UTF8)
Write-Host "Preparation-only manifest: $manifestPath"
if ($verdict -ne 'PASS') { exit 1 }
