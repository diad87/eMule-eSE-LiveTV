$ErrorActionPreference='Stop'
$runner=Join-Path $PSScriptRoot 'run_quic_product_pair.ps1'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($runner,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Runner parse errors'}
# Execute the actual runner clauses, not a second implementation of its oracle.
$blocks=@($ast.FindAll({param($a) $a -is [System.Management.Automation.Language.IfStatementAst] -and $a.Extent.Text.Contains('$dropMatches=')},$true))
$gates=@($ast.FindAll({param($a) $a -is [System.Management.Automation.Language.IfStatementAst] -and $a.Extent.Text.Contains('$pass=$pass -and $lossDrops -gt 0')},$true))
if($blocks.Count -ne 1 -or $gates.Count -ne 1){throw 'Ambiguous runner oracle; update test explicitly'}
$block=[scriptblock]::Create($blocks[0].Extent.Text)
$gate=[scriptblock]::Create($gates[0].Extent.Text)
foreach($case in @(@(0,0,$false),@(1,0,$true),@(0,1,$true),@(2,3,$true))){
    $NetworkLossMs=30000; $lossDrops=[UInt64]0; $pass=$true
    for($n=0;$n -lt 2;$n++){
        $role=@('upload','download')[$n]
        $text='QUIC_PAIR NETWORK_LOSS_'+$role.ToUpperInvariant()+' PASS milliseconds=30000 epoch=1 drops='+$case[$n]
        $marker=$true
        . $block
        $pass=$pass -and $marker
    }
    . $gate
    if($pass -ne $case[2]){throw "Loss gate failed: $($case -join ',')"}
}
foreach($text in @(
    'QUIC_PAIR NETWORK_LOSS_UPLOAD PASS milliseconds=30000 epoch=1',
    'QUIC_PAIR NETWORK_LOSS_UPLOAD PASS milliseconds=5000 drops=1',
    "QUIC_PAIR NETWORK_LOSS_UPLOAD PASS milliseconds=30000 drops=1`nQUIC_PAIR NETWORK_LOSS_UPLOAD PASS milliseconds=30000 drops=1")){
    $n=0; $role='upload'; $NetworkLossMs=30000; $lossDrops=[UInt64]0; $marker=$true
    . $block
    if($marker){throw 'Invalid or duplicate loss evidence accepted'}
}
Write-Output 'Pair loss oracle: 7 cases PASS (actual runner AST; not product/network acceptance)'
