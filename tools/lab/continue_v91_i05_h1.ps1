[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RunBase,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CandidateZipPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$FixturePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedFixtureSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$H3IPv4
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Ejecute esta utilidad desde una consola de PowerShell elevada.'
}

$operatorStatusPath = Join-Path $runBase 'CONTINUE-STATUS.json'
function Write-I05OperatorStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [string]$Message = ''
    )
    [pscustomobject][ordered]@{
        schema = 'ese.v91.i05-operator-status/v1'
        status = $Status
        updated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        process_id = $PID
        message = $Message
    } | ConvertTo-Json -Depth 3 |
        Set-Content -LiteralPath $operatorStatusPath -Encoding UTF8
}

Write-I05OperatorStatus -Status 'STARTING'
try {
$staleControlOwners = @(
    Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object {
            $_.RemotePort -eq 8012 -and
            [string]$_.State -eq 'Established'
        } |
        Select-Object -ExpandProperty OwningProcess -Unique
)
foreach ($processId in $staleControlOwners) {
    $stale = Get-CimInstance Win32_Process -Filter (
        "ProcessId = $processId"
    ) -ErrorAction Stop
    if ($null -eq $stale -or [string]$stale.Name -cne 'powershell.exe' -or
        [string]$stale.CommandLine -notlike
            '*continue_v91_i05_h1.ps1*') {
        throw 'El canal 8012 pertenece a un proceso no reconocido.'
    }
    Stop-Process -Id $processId -Force -ErrorAction Stop
}

$latestOwnedRun = Get-ChildItem (Join-Path $runBase 'runs') -Directory |
    Sort-Object CreationTimeUtc -Descending |
    Where-Object {
        Test-Path (Join-Path $_.FullName 'private\ownership.json')
    } |
    Select-Object -First 1
if ($null -ne $latestOwnedRun) {
    $owned = Get-Content (
        Join-Path $latestOwnedRun.FullName 'private\ownership.json'
    ) -Raw | ConvertFrom-Json
    $ownedProcessId = [int]$owned.process.process_id
    if ($ownedProcessId -gt 0 -and
        $null -ne (Get-Process -Id $ownedProcessId `
            -ErrorAction SilentlyContinue)) {
        & (Join-Path $PSScriptRoot 'cleanup_v91_i05_t1_source.ps1') `
            -RunRoot $latestOwnedRun.FullName -NoOpen
    }
}

$activeCoordinators = @(
    Get-CimInstance Win32_Process -ErrorAction Stop |
        Where-Object {
            $_.ProcessId -ne $PID -and
            [string]$_.CommandLine -like
                '*run_v91_i05_t1_source.ps1*'
        }
)
if ($activeCoordinators.Count -gt 0) {
    throw 'Ya existe una campaña V91-I05 activa en H1.'
}

$occupied = @(
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @(4711, 4662, 7862) }
)
if ($occupied.Count -gt 0) {
    throw 'Los puertos formales de H1 no quedaron libres.'
}

& (Join-Path $PSScriptRoot 'run_v91_i05_t1_source.ps1') `
    -CandidateZipPath $CandidateZipPath `
    -FixturePath $FixturePath `
    -ExpectedFixtureSha256 $ExpectedFixtureSha256 `
    -RunBase $runBase `
    -H3IPv4 $H3IPv4 `
    -ReadyTimeoutSeconds 1800 `
    -TransferTimeoutSeconds 7200 `
    -CompletionTimeoutSeconds 300

if ($LASTEXITCODE -ne 0) {
    throw "El coordinador H1 termino con codigo $LASTEXITCODE."
}
Write-I05OperatorStatus -Status 'PASS'
} catch {
    Write-I05OperatorStatus -Status 'ERROR' -Message $_.Exception.Message
    throw
}
