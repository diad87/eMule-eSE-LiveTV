param([string]$Root='D:\tmp\v93-a2-classic-vm-payload01')
$ErrorActionPreference='Stop'
$target=[IO.Path]::GetFullPath($Root)
if($target -ne 'D:\tmp\v93-a2-classic-vm-payload01' -or (Test-Path -LiteralPath $target)) { throw 'Only a new explicit payload directory is supported.' }
$ancestor=Get-Item -LiteralPath D:\tmp
while($ancestor) {
    if($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse ancestor.' }
    $ancestor=$ancestor.Parent
}
$references=@{
    Win32=@{path='D:\tmp\v93-a2-classic070b-reference01\eMule0.70b\eMule0.70b';sha='1FD7EEB62E9A93914644DC4FBD11E0C7AC37EE0A416EDF90F415EED7D9A7C105'};
    x64=@{path='D:\tmp\v93-a2-classic070b-reference01\eMule0.70b_x64\eMule0.70b';sha='FB56C326E6CC80F9E8BD8222127A0703CFFF936382C6EFE169A1F733FEE7D035'}
}
foreach($arch in @('x64','Win32')) {
    if((Get-FileHash -LiteralPath (Join-Path $references[$arch].path 'emule.exe')).Hash -ne $references[$arch].sha) { throw 'Original binary hash mismatch.' }
}
$null=New-Item -ItemType Directory -Path $target
$payload=Join-Path $target 'payload'; $null=New-Item -ItemType Directory -Path $payload
foreach($arch in @('x64','Win32')) {
    $classic=Join-Path $payload "classic-$arch"
    Copy-Item -LiteralPath $references[$arch].path -Destination $classic -Recurse
    if((Get-FileHash -LiteralPath (Join-Path $classic 'emule.exe')).Hash -ne $references[$arch].sha) { throw 'Copied classic binary changed.' }
    $ese=Join-Path $payload "ese-$arch"; $null=New-Item -ItemType Directory -Path $ese
    Copy-Item -LiteralPath "D:\tmp\v93-native-mfc-$arch-out\emule.exe" -Destination (Join-Path $ese 'emule.exe')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\srchybrid\eMule.tmpl') -Destination (Join-Path $ese 'eMule.tmpl')
    $native="D:\tmp\ese-quic-c1-pinned-$arch-20260930"
    & (Join-Path $PSScriptRoot 'verify_quic_host_dependencies.ps1') -Root $native -Architecture $arch
    if(!$?) { throw 'Native dependency validation failed.' }
    $manifest=Get-Content -LiteralPath (Join-Path $native "manifest-$arch.json") -Raw | ConvertFrom-Json
    foreach($record in $manifest.outputs | Where-Object { $_.name -like '*.dll' }) {
        if($record.name -ne [IO.Path]::GetFileName($record.name)) { throw 'Unsafe dependency name.' }
        $destination=Join-Path $ese $record.name
        Copy-Item -LiteralPath (Join-Path $native "probe-$arch\Release\$($record.name)") -Destination $destination
        if((Get-FileHash -LiteralPath $destination).Hash -ne $record.sha256) { throw 'Dependency copy mismatch.' }
    }
}
$files=@(Get-ChildItem -LiteralPath $payload -Recurse -File | ForEach-Object {
    if($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Payload cannot contain reparse files.' }
    @{relative_path=$_.FullName.Substring($payload.Length+1);bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}
})
$report=@{schema='ese.v93.classic-vm-payload/1';created_utc=[DateTime]::UtcNow.ToString('o');
    binaries_executed=$false;vm_created=$false;acceptance='NOT_RUN';files=$files;
    intended_guest='Windows64 Hyper-V isolated VM; Win32 and x64 application tests, not Windows32 OS coverage'}
[IO.File]::WriteAllText((Join-Path $payload 'payload-manifest.json'),($report|ConvertTo-Json -Depth 6),[Text.Encoding]::UTF8)
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($payload,(Join-Path $target 'classic-lab-payload.zip'))
Write-Output "Payload prepared only; no clients launched: $target"
