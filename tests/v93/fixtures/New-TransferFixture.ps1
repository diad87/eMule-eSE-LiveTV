param(
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [ValidateSet('EMPTY','BYTE','BLOCK','PART','PART_PLUS_ONE','F1','F2','F3')][string]$Fixture='BLOCK'
)
$ErrorActionPreference='Stop'
$definitions=@{
    EMPTY=@(0L,'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    BYTE=@(1L,'6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d')
    BLOCK=@(184320L,'60001e9b94b5ce7c31b9f3a3bfe12b88a1bc78a36af67928a94d90cf32cba1f2')
    PART=@(9728000L,'8585702068cf4e04aeeae038e77ce99a9587012b8e843c29ae0f49bac18aef42')
    PART_PLUS_ONE=@(9728001L,'19c6a8d59900cd17c25b1e3641d94397231480c8ca25a4619546dba35b40874e')
    F1=@(1073741824L,'2c06ade942ee3f17a048dd1064b2fab046a4bb95386d8bb41b68dc6711ac2af3')
    F2=@(1048576L,'fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83')
    F3=@(4294967297L,'050986594fc2bb1bd0c749b8bed867d9c2422e499ec4079525abc0381e9d36cb')
}
$target=[IO.Path]::GetFullPath($OutputPath)
$definition=$definitions[$Fixture]
$block=New-Object byte[] 1048576
for($index=0;$index -lt $block.Length;$index++) { $block[$index]=[byte]($index % 256) }
# CreateNew forbids overwriting a profile, fixture or user file. No automatic
# cleanup on failure: preserve the exact failed artifact for diagnosis.
$stream=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {
    $remaining=[long]$definition[0]
    while($remaining -gt 0) {
        $count=[int][Math]::Min($remaining,[long]$block.Length)
        $stream.Write($block,0,$count)
        $remaining-=$count
    }
    $stream.Flush($true)
} finally { $stream.Dispose() }
$actual=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
if((Get-Item -LiteralPath $target).Length -ne $definition[0] -or $actual -ne $definition[1]) {
    throw "Fixture verification failed; artifact preserved at $target (SHA256=$actual)"
}
[pscustomobject]@{ fixture=$Fixture; path=$target; bytes=[long]$definition[0]; sha256=$actual; verified=$true }
