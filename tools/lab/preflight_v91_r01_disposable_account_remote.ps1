[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [Alias('JobRequestPath')]
    [string]$RequestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$request = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
if ([string]$request.schema -cne
        'ese.v91.r01-disposable-account-preflight-request/v1' -or
    [string]$request.expected_candidate_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [Int64]$request.expected_candidate_bytes -le 0) {
    throw 'Invalid disposable-account preflight request.'
}
$candidatePath = [IO.Path]::GetFullPath(
    [string]$request.candidate_zip_path)

function Get-R01StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)) |
                    ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ([string]$identity.User.Value -ceq 'S-1-5-18') {
    throw 'Disposable account preflight ran as SYSTEM.'
}
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Disposable account is not elevated administrator.'
}
$task = Get-ScheduledTask -TaskName 'eSE Lab R01 Disposable Agent' `
    -ErrorAction Stop
$taskUser = [string]$task.Principal.UserId
$taskUserLeaf = @($taskUser.Split('\'))[-1]
$identityUserLeaf = @(([string]$identity.Name).Split('\'))[-1]
if (-not [string]::Equals($taskUserLeaf, 'eSER01Lab',
        [StringComparison]::OrdinalIgnoreCase) -or
    -not [string]::Equals($identityUserLeaf, 'eSER01Lab',
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Disposable task principal is not the expected lab account.'
}

$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (-not (Test-Path -LiteralPath $runKey)) {
    New-Item -Path $runKey -Force | Out-Null
}
$autoStart = Get-ItemProperty -LiteralPath $runKey `
    -Name 'eMuleAutoStart' -ErrorAction SilentlyContinue
if ($null -ne $autoStart) {
    throw 'Disposable HKCU already contains eMuleAutoStart.'
}
$ed2kKey = 'HKCU:\Software\Classes\ed2k'
if (Test-Path -LiteralPath $ed2kKey) {
    throw 'Disposable HKCU already contains the ed2k subtree.'
}
if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
    throw 'Disposable candidate ZIP is missing.'
}
$candidate = Get-Item -LiteralPath $candidatePath
$candidateSha256 = (Get-FileHash -LiteralPath $candidatePath `
    -Algorithm SHA256).Hash.ToLowerInvariant()
if ([Int64]$candidate.Length -ne [Int64]$request.expected_candidate_bytes -or
    $candidateSha256 -cne [string]$request.expected_candidate_sha256) {
    throw 'Disposable candidate ZIP binding mismatch.'
}
$profile = @(Get-CimInstance -ClassName Win32_UserProfile | Where-Object {
    [string]$_.SID -ceq [string]$identity.User.Value
})
if ($profile.Count -ne 1 -or -not [bool]$profile[0].Loaded) {
    throw 'Disposable Windows profile is not uniquely loaded.'
}

[pscustomobject][ordered]@{
    schema = 'ese.v91.r01-disposable-account-preflight/v1'
    status = 'PASS'
    identity_is_system = $false
    identity_sid_sha256 = Get-R01StringSha256 -Value (
        [string]$identity.User.Value)
    identity_name_sha256 = Get-R01StringSha256 -Value ([string]$identity.Name)
    administrator = $true
    task_state = [string]$task.State
    task_principal_matches = $true
    profile_loaded = $true
    run_key_exists = Test-Path -LiteralPath $runKey
    emule_autostart_absent = $true
    ed2k_subtree_absent = $true
    emule_process_count = @(Get-Process -Name emule `
        -ErrorAction SilentlyContinue).Count
    candidate_zip_sha256 = $candidateSha256
    candidate_zip_bytes = [Int64]$candidate.Length
} | ConvertTo-Json -Compress
