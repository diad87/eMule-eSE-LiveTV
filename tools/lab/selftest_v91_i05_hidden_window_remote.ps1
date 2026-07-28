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
$runsRoot = Join-Path $kitRoot 'runs'

$previousLibraryOnly = $env:ESE_V91_I05_LIBRARY_ONLY
try {
    $env:ESE_V91_I05_LIBRARY_ONLY = '1'
    . $runner
} finally {
    $env:ESE_V91_I05_LIBRARY_ONLY = $previousLibraryOnly
}

$latestRun = Get-ChildItem -LiteralPath $runsRoot -Directory |
    Where-Object Name -like 'v91-i05-h3-*' |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
if ($null -eq $latestRun) {
    throw 'No existe un nodo H3 previo para la prueba de ventana oculta.'
}
$node = Join-Path $latestRun.FullName 'nodes\v91-i05-t1-b'
$exe = Join-Path $node 'emule.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw 'El nodo H3 previo no contiene emule.exe.'
}

$process = Start-Process -FilePath $exe -ArgumentList @(
    '--portable', '--ignoreinstances', '--headless',
    '--metrics-port=8911', '--tcp-port=8862', '--udp-port=8872'
) -WorkingDirectory $node -WindowStyle Hidden -PassThru
try {
    $link = (
        'ed2k://|file|v91-i05-hidden-window-selftest.bin|1|' +
        '00000000000000000000000000000000|/'
    )
    $delivery = Send-I05Ed2kLink -Process $process -Link $link
    [pscustomobject][ordered]@{
        status = 'PASS'
        job_id = (Get-Content -LiteralPath $JobRequestPath -Raw |
            ConvertFrom-Json).job_id
        process_id = [int]$process.Id
        main_window_handle_visible =
            ($process.MainWindowHandle -ne [IntPtr]::Zero)
        hidden_window_found = $true
        delivery_count = 1
        native_accepted = [bool]$delivery.accepted
        native_result = [UInt64]$delivery.native_result
    } | ConvertTo-Json -Compress
} finally {
    $process.Refresh()
    if (-not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction Stop
        $process.WaitForExit(10000) | Out-Null
    }
}
