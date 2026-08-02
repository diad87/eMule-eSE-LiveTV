[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
$jobRoot = Split-Path -Parent ([IO.Path]::GetFullPath($JobRequestPath))
$jobsRoot = Split-Path -Parent $jobRoot
$kitRoot = Split-Path -Parent $jobsRoot
$runner = Join-Path $kitRoot 'run_v91_i05_downloader_kit.ps1'
$etlPath = Join-Path $jobRoot 'etw-stop-probe.etl'

$null = @(& logman.exe query -ets PktMon 2>&1)
if ($LASTEXITCODE -eq 0) {
    throw 'Ya existe una sesion PktMon; se rechaza el probe.'
}

$previousLibraryOnly = $env:ESE_V91_I05_LIBRARY_ONLY
$started = $false
$filterAdded = $false
$filterName = 'ese-i05-etw-probe-' + (
    [Guid]::NewGuid().ToString('N').Substring(0, 8))
try {
    $env:ESE_V91_I05_LIBRARY_ONLY = '1'
    . $runner
    $beforeFilters = @(& pktmon.exe filter list 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'No se pudo inventariar filtros antes del probe.'
    }
    $filterOutput = @(& pktmon.exe filter add $filterName `
        -i 127.0.0.1 -t TCP 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "No se pudo crear el filtro probe: $($filterOutput -join ' ')"
    }
    $filterAdded = $true
    $armedFilters = @(& pktmon.exe filter list 2>&1)
    if ($LASTEXITCODE -ne 0 -or
        ($armedFilters -join "`n").IndexOf(
            $filterName, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw 'El filtro probe no quedo armado.'
    }
    $startOutput = @(& pktmon.exe start --capture --pkt-size 64 `
        --file-name $etlPath --file-size 16 --log-mode circular 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "No se pudo iniciar PktMon: $($startOutput -join ' ')"
    }
    $started = $true
    Start-Sleep -Seconds 1
    $loss = Get-I05EtwLossEvidence -StopOwnedSession
    $started = $false
    if (-not [bool]$loss.proved_zero -or
        [UInt32]$loss.error_code -ne 0) {
        throw "El STOP ETW no quedo probado: $($loss.error_code)"
    }
    $beforeResetFilters = @(& pktmon.exe filter list 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'No se pudo inventariar filtros antes del reset.'
    }
    Assert-I05PktMonFilterRowsExact `
        -ExpectedLines $armedFilters -ActualLines $beforeResetFilters
    $resetOutput = @(& pktmon.exe stop 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "PktMon no reseteo su estado: $($resetOutput -join ' ')"
    }
    $removeOutput = @(& pktmon.exe filter remove 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "No se pudo retirar el filtro probe: $($removeOutput -join ' ')"
    }
    $filterAdded = $false
    $afterFilters = @(& pktmon.exe filter list 2>&1)
    if ($LASTEXITCODE -ne 0 -or
        ($afterFilters -join "`n").Trim() -cne
            ($beforeFilters -join "`n").Trim()) {
        throw 'PktMon no restauro el inventario inicial.'
    }
    [pscustomobject][ordered]@{
        schema = 'ese.v91.i05-etw-stop-probe/v1'
        status = 'PASS'
        loss = $loss
        etl_bytes = [Int64](Get-Item -LiteralPath $etlPath).Length
    } | ConvertTo-Json -Depth 5 -Compress
} finally {
    $env:ESE_V91_I05_LIBRARY_ONLY = $previousLibraryOnly
    if ($started) {
        & pktmon.exe stop 2>&1 | Out-Null
    }
    if ($filterAdded) {
        & pktmon.exe filter remove 2>&1 | Out-Null
    }
}
