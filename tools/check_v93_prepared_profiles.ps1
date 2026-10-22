param([Parameter(Mandatory=$true)][string]$ProfilesRoot,
      [Parameter(Mandatory=$true)][string]$OutFile)
$ErrorActionPreference='Stop'
$root=(Resolve-Path -LiteralPath $ProfilesRoot).Path
if(!$root.StartsWith('D:\tmp\',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'This preparation check only accepts isolated D:\tmp profiles.'
}
if(Test-Path -LiteralPath $OutFile) { throw 'Evidence output must be new.' }
$rows=@(foreach($name in @('profile-A','profile-B')) {
    $profile=(Resolve-Path -LiteralPath (Join-Path $root $name)).Path
    if((Get-Item -LiteralPath $profile).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Profile cannot be a reparse point.'
    }
    $config=Join-Path $profile 'config'
    if((Get-Item -LiteralPath $config).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Config cannot be a reparse point.'
    }
    $ini=Join-Path $config 'preferences.ini'
    $content=Get-Content -LiteralPath $ini -Raw
    foreach($setting in @('AutoConnect=0','EnableUPnP=0','EseNetLabEnabled=0','Enabled=0')) {
        if($content -notmatch ('(?m)^'+[regex]::Escape($setting)+'\r?$')) {
            throw "Missing preparation setting $setting in $name"
        }
    }
    $port=[regex]::Match($content,'(?m)^Port=(\d+)\r?$')
    $udp=[regex]::Match($content,'(?m)^UDPPort=(\d+)\r?$')
    if(!$port.Success -or !$udp.Success) { throw 'Missing explicit ports.' }
    $probe=Join-Path $config ('v93-access-'+[guid]::NewGuid().ToString('N')+'.tmp')
    $created=$false
    try {
        $stream=[IO.File]::Open($probe,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $created=$true
        try { $stream.WriteByte(93); $stream.Position=0; if($stream.ReadByte() -ne 93) { throw 'Readback failed.' } }
        finally { $stream.Dispose() }
    } finally { if($created) { Remove-Item -LiteralPath $probe } }
    [ordered]@{path=$profile;config=$config;config_read_write_access=$true;
        tcp_port=[int]$port.Groups[1].Value;udp_port=[int]$udp.Groups[1].Value;
        ini_sha256=(Get-FileHash -LiteralPath $ini).Hash;
        executable_sha256=(Get-FileHash -LiteralPath (Join-Path $profile 'emule.exe')).Hash}
})
if($rows[0].tcp_port -eq $rows[1].tcp_port -or $rows[0].udp_port -eq $rows[1].udp_port) {
    throw 'Profiles must have distinct ports.'
}
$result=[ordered]@{schema='ese.v93.prepared-profile-access/1';generated_utc=[DateTime]::UtcNow.ToString('o');
    profiles=$rows;runtime_launched=$false;runtime_isolation_verified=$false;personal_profile_accessed=$false}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutFile),($result|ConvertTo-Json -Depth 6),[Text.Encoding]::UTF8)
Write-Output 'PASS: two prepared profiles accessible; no runtime isolation claim.'
