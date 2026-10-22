param([Parameter(Mandatory=$true)][string]$ProfileRoot,
      [ValidateRange(10,9000)][int]$DurationSeconds=8400,
      [string]$DashboardExecutable='')
$ErrorActionPreference='Stop'
$root=(Resolve-Path -LiteralPath $ProfileRoot).Path
if(!$root.StartsWith('D:\tmp\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Only prepared D:\tmp profiles.' }
$ancestor=Get-Item -LiteralPath $root
while($ancestor) {
    if($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse ancestor.' }
    $ancestor=$ancestor.Parent
}
$manifest=Get-Content -LiteralPath (Join-Path $root 'prepared.json') -Raw | ConvertFrom-Json
if($manifest.profile -ne $root -or $manifest.schema -ne 'ese.v93.reach-binding-lab/1') { throw 'Invalid preparation.' }
$exe=Join-Path $root 'emule.exe'
if((Get-FileHash -LiteralPath $exe).Hash -ne $manifest.executable_sha256 -or
   (Get-FileHash -LiteralPath (Join-Path $root 'config/preferences.ini')).Hash -ne $manifest.preferences_sha256) { throw 'Changed prepared inputs.' }
foreach($record in $manifest.native_runtime_inputs) {
    if($record.name -ne [IO.Path]::GetFileName($record.name) -or
        (Get-FileHash -LiteralPath (Join-Path $root $record.name)).Hash -ne $record.sha256) { throw 'Invalid dependency.' }
}
$events=Join-Path $root 'config/soak-events.txt'
$out=Join-Path $root 'soak-result.json'
if((Test-Path -LiteralPath $events) -or (Test-Path -LiteralPath $out)) { throw 'Previously used profile.' }
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SoakWindow {
 [DllImport("user32.dll", SetLastError=true)] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
 [DllImport("user32.dll", SetLastError=true)] public static extern bool PostMessage(IntPtr h,uint m,UIntPtr w,IntPtr l);
 [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr SendMessageTimeout(IntPtr h,uint m,UIntPtr w,IntPtr l,uint flags,uint timeout,out UIntPtr result);
}
'@
$result=[ordered]@{schema='ese.v93.kad2-gui-soak/1';profile=$root;exe_sha256=$manifest.executable_sha256;
    requested_seconds=$DurationSeconds;started_utc=[DateTime]::UtcNow.ToString('o');verdict='RUNNING';
    scope='isolated loopback actual Kad2 index10000, real modal pump/UploadTimer, normal WM_CLOSE; no public network';
    samples=0;max_ui_response_ms=0;phases=@()}
function Save-Result { [IO.File]::WriteAllText($out,($result|ConvertTo-Json -Depth 8),[Text.Encoding]::UTF8) }
function Owned-Window($process,$phase) {
    $deadline=[Diagnostics.Stopwatch]::StartNew()
    do {
        if($process.HasExited) { throw "Early exit=$($process.ExitCode) before $phase" }
        if(Test-Path -LiteralPath $events) {
            $line=Get-Content -LiteralPath $events | Where-Object { $_ -like "$phase *" } | Select-Object -Last 1
            if($line -and $line -match 'pid=(\d+) hwnd=(\d+) sources=10000') {
                if([int]$Matches[1] -ne $process.Id) { throw 'Wrong event owner.' }
                $window=[IntPtr]([long]$Matches[2]); [uint32]$owner=0
                $null=[SoakWindow]::GetWindowThreadProcessId($window,[ref]$owner)
                if($owner -ne $process.Id) { throw 'Wrong window owner.' }
                return $window
            }
        }
        Start-Sleep -Milliseconds 100
    } while($deadline.Elapsed.TotalSeconds -lt 30)
    throw "Ready deadline: $phase"
}
function Close-Owned($process,$window,$phase) {
    [uint32]$owner=0; $null=[SoakWindow]::GetWindowThreadProcessId($window,[ref]$owner)
    if($owner -ne $process.Id) { throw 'Close owner mismatch.' }
    $beforeText=Get-Content -LiteralPath $events -Raw
    $beforeCount=([regex]::Matches($beforeText,'CLOSE_ENTER')).Count
    $watch=[Diagnostics.Stopwatch]::StartNew()
    if(![SoakWindow]::PostMessage($window,0x10,[UIntPtr]::Zero,[IntPtr]::Zero)) { throw 'WM_CLOSE post failed.' }
    do {
        $text=if(Test-Path -LiteralPath $events){Get-Content -LiteralPath $events -Raw}else{''}
        if(([regex]::Matches($text,'CLOSE_ENTER')).Count -gt $beforeCount) { break }
        if($process.HasExited) { break }
        Start-Sleep -Milliseconds 10
    } while($watch.Elapsed.TotalSeconds -lt 1)
    $accepted=$watch.Elapsed.TotalMilliseconds
    if(([regex]::Matches($text,'CLOSE_ENTER')).Count -le $beforeCount -or $accepted -gt 1000) { throw 'GUI did not accept normal close within1s.' }
    if(!$process.WaitForExit([Math]::Max(1,30000-[int]$watch.Elapsed.TotalMilliseconds))) { throw 'Full shutdown exceeded30s.' }
    $drain=$watch.Elapsed.TotalMilliseconds
    $text=Get-Content -LiteralPath $events -Raw
    if($process.ExitCode -ne 0 -or !$text.Contains('CLOSE_DONE') -or $text -notmatch 'CLOSE_ENTER[^\r\n]*sources=10000') { throw 'Invalid normal closure/index count.' }
    $result.phases+=@{phase=$phase;pid=$process.Id;close_accept_ms=$accepted;full_exit_ms=$drain;exit_code=$process.ExitCode}
    Save-Result
}
$process=$null
$launchEnvironment=@{}
if($DashboardExecutable) {
    if(!$manifest.diagnostic_web_port) { throw 'Dashboard test requires prepared diagnostic WebUI.' }
    $webProbe=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,[int]$manifest.diagnostic_web_port)
    try { $webProbe.Start() } finally { $webProbe.Stop() }
    $package=Get-Item -LiteralPath $DashboardExecutable
    if($package.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse package.' }
    $destination=Join-Path $root 'ese-server.exe'
    if(Test-Path -LiteralPath $destination) { throw 'Existing dashboard package.' }
    Copy-Item -LiteralPath $package.FullName -Destination $destination
    $result.dashboard_sha256=(Get-FileHash -LiteralPath $destination).Hash
    if($result.dashboard_sha256 -ne (Get-FileHash -LiteralPath $package.FullName).Hash) { throw 'Package copy changed.' }
    $launchEnvironment=@{ESE_KAD2_DASHBOARD='1';ESE_TEST_MODE='1';ESE_BIND_HOST='127.0.0.1';ESE_PORT='8080';
        USERPROFILE=$root;TEMP=(Join-Path $root 'Temp');TMP=(Join-Path $root 'Temp')}
    $result.dashboard_runs=@()
}
function Check-Dashboard($parent) {
    if(!$DashboardExecutable) { return }
    $marker=Join-Path $root 'config/ese-dashboard.endpoint'
    $deadline=[Diagnostics.Stopwatch]::StartNew()
    do {
        $line=if(Test-Path -LiteralPath $marker){Get-Content -LiteralPath $marker -Raw}else{''}
        if($line -match '^(\d+) (\d+)\s*$') {
            $childId=[int]$Matches[1]; $port=[int]$Matches[2]
            $child=Get-CimInstance Win32_Process -Filter "ProcessId=$childId"
            if($child -and $child.ParentProcessId -eq $parent.Id -and $child.ExecutablePath -eq (Join-Path $root 'ese-server.exe')) { break }
        }
        Start-Sleep -Milliseconds 100
    } while($deadline.Elapsed.TotalSeconds -lt 20)
    if(!$child -or $child.ParentProcessId -ne $parent.Id -or $port -lt 8080 -or $port -gt 8090) { throw 'Dashboard owner/marker deadline.' }
    $handler=[Net.Http.HttpClientHandler]::new(); $handler.UseProxy=$false
    $http=[Net.Http.HttpClient]::new($handler); $http.Timeout=[TimeSpan]::FromSeconds(3)
    try {
        $response=$http.GetAsync("http://127.0.0.1:$port/").GetAwaiter().GetResult()
        $body=$response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if([int]$response.StatusCode -ne 200 -or $body.Length -lt 100 -or $body -notmatch '<html|<!DOCTYPE') { throw 'Incomplete dashboard HTML.' }
        $loginWatch=[Diagnostics.Stopwatch]::StartNew(); $loggedIn=$false
        do {
            $status=$http.GetAsync("http://127.0.0.1:$port/api/emule/status").GetAwaiter().GetResult()
            if([int]$status.StatusCode -eq 200) {
                $state=$status.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
                $loggedIn=$state.loggedIn -eq $true
            }
            $status.Dispose()
            if(!$loggedIn) { Start-Sleep -Milliseconds 200 }
        } while(!$loggedIn -and $loginWatch.Elapsed.TotalSeconds -lt 15)
        if(!$loggedIn) {
            $result.dashboard_auth_failure=@{parent_pid=$parent.Id;http_status=[int]$status.StatusCode;reason=$state.reason}
            $diagnostics=$http.GetStringAsync("http://127.0.0.1:$port/api/ese/log?n=200").GetAwaiter().GetResult() | ConvertFrom-Json
            $result.dashboard_auth_failure.backend_port_log=@($diagnostics.items | Where-Object { $_ -match '\[eMule test\] WebUI port=\d+$' })
            $result.dashboard_auth_failure.parent_listeners=@(Get-NetTCPConnection -OwningProcess $parent.Id -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort)
            throw "Dashboard did not authenticate to isolated parent WebUI: $($state.reason)"
        }
        $result.dashboard_runs+=@{parent_pid=$parent.Id;child_pid=$childId;port=$port;http_status=200;html_characters=$body.Length;backend_logged_in=$true}
    } finally { $http.Dispose(); $handler.Dispose() }
}
try {
    Save-Result
    $env:ESE_KAD2_SOAK='seed'
    $process=Start-Process -FilePath $exe -ArgumentList @('--portable','--reach-binding-selftest','--ignoreinstances') -WorkingDirectory $root -WindowStyle Hidden -Environment $launchEnvironment -PassThru
    $null=$process.Handle; $result.seed_pid=$process.Id
    $window=Owned-Window $process 'READY_SEED'
    Check-Dashboard $process
    $watch=[Diagnostics.Stopwatch]::StartNew(); $result.ready_utc=[DateTime]::UtcNow.ToString('o')
    while($watch.Elapsed.TotalSeconds -lt $DurationSeconds) {
        if($process.HasExited) { throw "Unexpected exit=$($process.ExitCode) during soak." }
        [UIntPtr]$reply=[UIntPtr]::Zero
        $latency=[Diagnostics.Stopwatch]::StartNew()
        $ok=[SoakWindow]::SendMessageTimeout($window,0,[UIntPtr]::Zero,[IntPtr]::Zero,2,1000,[ref]$reply)
        $ms=$latency.Elapsed.TotalMilliseconds
        if($ok -eq [IntPtr]::Zero -or $ms -gt 1000) { throw 'UI heartbeat exceeded1s.' }
        $result.samples++; $result.max_ui_response_ms=[Math]::Max($result.max_ui_response_ms,$ms)
        $result.elapsed_seconds=$watch.Elapsed.TotalSeconds; Save-Result
        Write-Host ("SOAK elapsed={0:N1}s/{1}s pid={2} samples={3} maxUI={4:N1}ms" -f $watch.Elapsed.TotalSeconds,$DurationSeconds,$process.Id,$result.samples,$result.max_ui_response_ms)
        Start-Sleep -Seconds ([Math]::Min(30,[Math]::Max(1,[int][Math]::Ceiling($DurationSeconds-$watch.Elapsed.TotalSeconds))))
    }
    $result.elapsed_seconds=$watch.Elapsed.TotalSeconds
    $timerLines=@(Get-Content -LiteralPath $events | Where-Object { $_ -like 'UPLOAD_TIMER_KAD_PROCESS *' })
    $result.normal_kad_timer_samples=$timerLines.Count
    if($DurationSeconds -ge 8400 -and ($timerLines.Count -lt 110 -or
        @($timerLines | Where-Object { $_ -notmatch 'sources=10000$' }).Count)) {
        throw 'Normal Kad timer/index continuity not demonstrated.'
    }
    Close-Owned $process $window 'seed-normal-close'
    $file=Get-Item -LiteralPath (Join-Path $root 'config/src_index.dat')
    if($file.Length -le 100000 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid persisted index.' }
    $result.persisted_bytes=$file.Length; $result.persisted_sha256=(Get-FileHash -LiteralPath $file.FullName).Hash
    # Same owned profile; no preparation/overwrite. Real loader must recover all entries.
    $env:ESE_KAD2_SOAK='reload'
    $process=Start-Process -FilePath $exe -ArgumentList @('--portable','--reach-binding-selftest','--ignoreinstances') -WorkingDirectory $root -WindowStyle Hidden -Environment $launchEnvironment -PassThru
    $null=$process.Handle; $window=Owned-Window $process 'READY_RELOAD'
    Check-Dashboard $process
    # Remove seed close markers only from observation memory, not the evidence file.
    # CLOSE_ENTER for reload is checked after closure as a distinct occurrence below.
    Close-Owned $process $window 'reload-normal-close'
    $text=Get-Content -LiteralPath $events -Raw
    if(([regex]::Matches($text,'CLOSE_DONE')).Count -ne 2 -or ([regex]::Matches($text,'CLOSE_ENTER[^\r\n]*sources=10000')).Count -ne 2) { throw 'Both normal closes not recorded.' }
    foreach($run in $result.dashboard_runs) {
        if(Get-Process -Id $run.child_pid -ErrorAction SilentlyContinue) { throw 'Owned dashboard child survived normal parent close.' }
    }
    $result.verdict='PASS'; $result.exit20=if($DurationSeconds -ge 8400){'NOT_REPRODUCED'}else{'SMOKE_ONLY'}
    $result.finished_utc=[DateTime]::UtcNow.ToString('o'); Save-Result
    Write-Host "PASS $out"
} catch {
    $result.verdict='FAIL'; $result.error=$_.Exception.Message
    $result.finished_utc=[DateTime]::UtcNow.ToString('o'); Save-Result
    if($DashboardExecutable -and $process) {
        foreach($child in @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($process.Id)")) {
            if($child.ExecutablePath -eq (Join-Path $root 'ese-server.exe')) {
                $owned=Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue
                if($owned -and !$owned.HasExited) { $null=$owned.Handle; $owned.Kill(); $owned.WaitForExit(5000) | Out-Null }
            }
        }
    }
    if($process -and !$process.HasExited) { $process.Kill(); $process.WaitForExit(5000) | Out-Null }
    throw
} finally { Remove-Item Env:ESE_KAD2_SOAK -ErrorAction SilentlyContinue }
