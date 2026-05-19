# enable_crash_dumps.ps1 -- Turn on Windows Error Reporting LocalDumps for
# emule.exe so the NEXT crash automatically writes a full minidump to
# %LOCALAPPDATA%\CrashDumps\ without the user having to click anything.
#
# Run ONCE, as Administrator (HKLM requires elevation). After this, any
# subsequent emule.exe crash drops a .dmp file you can load in WinDbg
# alongside emule.pdb to see the actual offending call stack -- not just
# the "BaseClient.obj +0xe23b3" offset we've been guessing at.
#
# To revert later:  Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\emule.exe' -Recurse

[CmdletBinding()]
param(
    [string]$Process    = 'emule.exe',
    [string]$DumpFolder = "$env:LOCALAPPDATA\CrashDumps",
    [int]   $DumpCount  = 10,
    # DumpType: 1 = mini (small, ~64 KB, stack + module list)
    #           2 = full (process memory, big but actionable)
    [int]   $DumpType   = 2
)

$ErrorActionPreference = 'Stop'

# Are we elevated?
$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: this script needs admin (HKLM write). Right-click PowerShell -> Run as administrator." -ForegroundColor Red
    exit 1
}

$base = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
$key  = Join-Path $base $Process

if (-not (Test-Path $base)) { New-Item -Path $base -Force | Out-Null }
if (-not (Test-Path $key))  { New-Item -Path $key  -Force | Out-Null }

# DumpFolder is REG_EXPAND_SZ so %LOCALAPPDATA% inside it expands correctly
# regardless of which user later crashes emule.exe.
New-ItemProperty -Path $key -Name 'DumpFolder' -PropertyType ExpandString -Value $DumpFolder -Force | Out-Null
New-ItemProperty -Path $key -Name 'DumpCount'  -PropertyType DWord        -Value $DumpCount  -Force | Out-Null
New-ItemProperty -Path $key -Name 'DumpType'   -PropertyType DWord        -Value $DumpType   -Force | Out-Null

if (-not (Test-Path $DumpFolder)) {
    New-Item -ItemType Directory -Path $DumpFolder -Force | Out-Null
}

$typeName = switch ($DumpType) { 1 {'mini'} 2 {'full'} default {"custom($DumpType)"} }
Write-Host ""
Write-Host "OK -- WER LocalDumps enabled for $Process" -ForegroundColor Green
Write-Host "  DumpFolder : $DumpFolder"
Write-Host "  DumpType   : $typeName"
Write-Host "  DumpCount  : $DumpCount (older dumps overwritten beyond this)"
Write-Host ""
Write-Host "Next crash will silently drop $Process.<PID>.dmp into the folder above." -ForegroundColor Cyan
Write-Host "Open it with WinDbg: File -> Open Crash Dump, then symbols:"
Write-Host "  .sympath srv*$env:LOCALAPPDATA\Symbols*https://msdl.microsoft.com/download/symbols;<path-to-emule.pdb>"
