[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
$session = @(& logman.exe query -ets PktMon 2>&1)
if ($LASTEXITCODE -eq 0) {
    throw 'Existe una sesion PktMon activa; se rechaza limpiar filtros.'
}

$filters = @(& pktmon.exe filter list 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw 'No se pudo inventariar PktMon.'
}
$text = $filters -join "`n"
$names = @([regex]::Matches(
    $text,
    '(?im)^\s*\d+\s+(ese-i05-[a-z0-9-]+)\s'
) | ForEach-Object { $_.Groups[1].Value })
if ($names.Count -lt 1) {
    throw 'No se encontro ningun filtro eSE atribuible.'
}
foreach ($name in $names) {
    if ($name -cnotmatch (
            '^ese-i05-(?:[0-9a-f]{8}-' +
            '(?:v4-data|v6-(?:src|dst)-(?:tcp|udp))|' +
            'etw-probe-[0-9a-f]{8})$')) {
        throw "Filtro eSE no reconocido: $name"
    }
}
$foreignRows = @($text -split "`r?`n" | Where-Object {
    $_ -match '^\s*\d+\s+\S+' -and
    $_ -notmatch '^\s*\d+\s+ese-i05-[a-z0-9-]+\s'
})
if ($foreignRows.Count -ne 0) {
    throw 'Hay filtros ajenos; no se altera el inventario global.'
}

$remove = @(& pktmon.exe filter remove 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "PktMon no retiro los filtros eSE: $($remove -join ' ')"
}
$after = @(& pktmon.exe filter list 2>&1)
if ($LASTEXITCODE -ne 0 -or
    ($after -join "`n") -match '(?im)^\s*\d+\s+\S+') {
    throw 'El inventario PktMon no quedo vacio.'
}

[pscustomobject][ordered]@{
    schema = 'ese.v91.i05-pktmon-cleanup/v1'
    status = 'CLEANUP_COMPLETE'
    removed_filter_names = $names
    etw_session_absent = $true
    inventory_empty = $true
} | ConvertTo-Json -Depth 4 -Compress
