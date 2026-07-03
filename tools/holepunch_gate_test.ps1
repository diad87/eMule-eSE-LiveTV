<#
.SYNOPSIS
  GATE R.0 field harness — 2-PC hole-punch validation (Fase 0).
  Captures /api/status baseline, fires cross /api/holepunch/test on a shared
  wall-clock window, and prints the net counter deltas. Run ONE copy per node.

.DESCRIPTION
  In a real 2-NAT test the two nodes live on different networks, so a single
  machine cannot reach the other node's loopback webserver (its /api/* is
  loopback-trust by design — exposing it would re-open the BUG-061 class of
  network-exposure holes). So this script runs LOCALLY on each node against
  127.0.0.1 and synchronizes the cross-fire via a shared -FireAt instant.

  The decision matrix is CROSS-node (A.success vs B.req_recv), which one node
  cannot see alone. Each run prints a one-line PASTE-BACK summary; paste both
  A's and B's lines together to fill the matrix (or feed the two -OutFile JSONs
  to -MergeA/-MergeB on one machine afterwards).

.PARAMETER Local
  Base URL of THIS node's eMule webserver. Default http://127.0.0.1:4711.

.PARAMETER PeerIp
  PUBLIC IP of the OTHER node.

.PARAMETER PeerUdpPort
  Kad/UDP port of the OTHER node (Preferences -> Connection, default 4672).

.PARAMETER Role
  "A" or "B" — label for the printout/paste-back only.

.PARAMETER FireAt
  Shared "HH:mm:ss" wall-clock instant for round 0. BOTH operators set the same
  value so the cross-fire lands inside the correlation window. Empty = fire now.

.PARAMETER Rounds
  Number of cross-fire rounds (default 4).

.PARAMETER IntervalSec
  Seconds between rounds (default 30). TWO limits constrain this, not one:
    - the /api/holepunch/test endpoint cooldown is 5s (WebServer.cpp), and
    - the RECEIVER's per-IP PacketTracking token-bucket is ~2/min/IP
      (PacketTracking.cpp: token = MIN2MS(1)/2) for the inbound REQ/ACK opcodes.
  The second one bites: firing faster than ~2/min at the same peer IP makes the
  REMOTE node throttle/ban the later REQs, which would show up as a false
  "REQ never reached" (red) on rounds 3+ — self-inflicted, not the NAT. Keep
  IntervalSec >= 30 so each round stays inside the per-IP budget.

.PARAMETER SettleSec
  Seconds to wait after firing before reading the "after" counters, so the
  peer's REQ/ACK round-trip has time to land (default 3).

.PARAMETER OutFile
  Optional path to write a JSON summary (for later -Merge).

.PARAMETER MergeA
  Path to node A's -OutFile JSON. With -MergeB, prints the cross-node verdict
  and exits (no firing). Run this on one machine after collecting both files.

.PARAMETER MergeB
  Path to node B's -OutFile JSON (see -MergeA).

.EXAMPLE
  # On node A (its peer is B at 203.0.113.7:4672), both fire at 14:30:00:
  .\holepunch_gate_test.ps1 -Role A -PeerIp 203.0.113.7 -PeerUdpPort 4672 -FireAt 14:30:00 -OutFile gate_A.json
  # On node B (its peer is A at 198.51.100.4:4672), SAME FireAt:
  .\holepunch_gate_test.ps1 -Role B -PeerIp 198.51.100.4 -PeerUdpPort 4672 -FireAt 14:30:00 -OutFile gate_B.json
  # Then on either machine with both JSONs copied over:
  .\holepunch_gate_test.ps1 -MergeA gate_A.json -MergeB gate_B.json

.NOTES
  Negative control (proves the harness, not the network): set the hole-punch
  kill-switch OFF in Preferences and run once — /api/holepunch/test must return
  "error":"holepunch_disabled" and NO counter moves. Then turn it back ON.
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
  [Parameter(ParameterSetName='Run')]
  [string]$Local = "http://127.0.0.1:4711",

  [Parameter(ParameterSetName='Run', Mandatory=$true)]
  [string]$PeerIp,

  [Parameter(ParameterSetName='Run', Mandatory=$true)]
  [int]$PeerUdpPort,

  [Parameter(ParameterSetName='Run')]
  [ValidateSet("A","B")]
  [string]$Role = "A",

  [Parameter(ParameterSetName='Run')]
  [string]$FireAt = "",

  [Parameter(ParameterSetName='Run')]
  [int]$Rounds = 4,

  [Parameter(ParameterSetName='Run')]
  [int]$IntervalSec = 30,

  [Parameter(ParameterSetName='Run')]
  [int]$SettleSec = 3,

  [Parameter(ParameterSetName='Run')]
  [string]$OutFile = "",

  [Parameter(ParameterSetName='Merge', Mandatory=$true)]
  [string]$MergeA,

  [Parameter(ParameterSetName='Merge', Mandatory=$true)]
  [string]$MergeB
)

$ErrorActionPreference = 'Stop'

# The seven hole-punch counters exposed by /api/status (eSE v9 GATE telemetry).
$CounterKeys = @(
  'hole_punch_attempts',
  'hole_punch_success',
  'hole_punch_req_recv',
  'hole_punch_challenge_sent',
  'hole_punch_sym_nat_fail',
  'hole_punch_encrypted',
  'hole_punch_plaintext'
)

function Get-HpStatus {
  param([string]$Base)
  try {
    $r = Invoke-RestMethod -Uri "$Base/api/status" -TimeoutSec 10
  } catch {
    throw "Cannot reach $Base/api/status — is the eMule webinterface enabled and the port correct? ($($_.Exception.Message))"
  }
  # Guard against an HTML login page / wrong endpoint masquerading as a 200:
  # a string body or a missing known counter means we did NOT get our JSON.
  if (($r -is [string]) -or ($r.PSObject.Properties.Name -notcontains 'hole_punch_attempts')) {
    throw "$Base/api/status did not return the expected JSON (got a login page or wrong build?). Run this on the node itself against 127.0.0.1, and make sure the build includes the GATE telemetry."
  }
  $h = @{}
  foreach ($k in $CounterKeys) {
    $v = $r.$k
    if ($null -eq $v) { $v = 0 }
    $h[$k] = [int64]$v
  }
  $h['utp_hole_punch_enabled'] = [bool]$r.utp_hole_punch_enabled
  $h['kad_connected']          = [bool]$r.kad_connected
  return $h
}

function Invoke-HpFire {
  param([string]$Base, [string]$Ip, [int]$Port)
  $uri = "$Base/api/holepunch/test?ip=$Ip&udp_port=$Port"
  try {
    return Invoke-RestMethod -Uri $uri -TimeoutSec 10
  } catch {
    Write-Warning "fire failed: $($_.Exception.Message)"
    return $null
  }
}

function Get-Delta {
  param($Before, $After)
  $d = @{}
  foreach ($k in $CounterKeys) { $d[$k] = $After[$k] - $Before[$k] }
  return $d
}

function Format-PasteBack {
  param([string]$RoleLabel, [int]$Rnds, $Tot)
  return ("GATE {0} | rounds={1} | dattempts={2} dsuccess={3} dreq_recv={4} dchallenge={5} dsymnat={6} denc={7} dplain={8}" -f `
    $RoleLabel, $Rnds, $Tot['hole_punch_attempts'], $Tot['hole_punch_success'], $Tot['hole_punch_req_recv'], `
    $Tot['hole_punch_challenge_sent'], $Tot['hole_punch_sym_nat_fail'], $Tot['hole_punch_encrypted'], $Tot['hole_punch_plaintext'])
}

# ─────────────────────────────────────────────────────────────────────────────
# MERGE MODE — combine two node JSONs into the cross-node verdict, no firing.
# ─────────────────────────────────────────────────────────────────────────────
if ($PSCmdlet.ParameterSetName -eq 'Merge') {
  $a = Get-Content -Raw -Path $MergeA | ConvertFrom-Json
  $b = Get-Content -Raw -Path $MergeB | ConvertFrom-Json

  Write-Host ""
  Write-Host "=== GATE R.0 cross-node verdict ===" -ForegroundColor Cyan
  Write-Host ("Node {0}: attempts+{1}  success+{2}  req_recv+{3}  challenge+{4}  symnat+{5}" -f `
    $a.role, $a.totals.hole_punch_attempts, $a.totals.hole_punch_success, $a.totals.hole_punch_req_recv, $a.totals.hole_punch_challenge_sent, $a.totals.hole_punch_sym_nat_fail)
  Write-Host ("Node {0}: attempts+{1}  success+{2}  req_recv+{3}  challenge+{4}  symnat+{5}" -f `
    $b.role, $b.totals.hole_punch_attempts, $b.totals.hole_punch_success, $b.totals.hole_punch_req_recv, $b.totals.hole_punch_challenge_sent, $b.totals.hole_punch_sym_nat_fail)
  Write-Host ""

  # A->B direction: A fired (attempts), did B receive (B.req_recv) and did A get the ACK (A.success)?
  function Show-Direction {
    param($Src, $Dst)
    $line = "{0}->{1}: " -f $Src.role, $Dst.role
    if ($Src.totals.hole_punch_success -gt 0) {
      Write-Host ($line + "PUNCH OK (success+$($Src.totals.hole_punch_success), $($Dst.role).req_recv+$($Dst.totals.hole_punch_req_recv))") -ForegroundColor Green
    } elseif ($Dst.totals.hole_punch_req_recv -gt 0) {
      Write-Host ($line + "REQ arrived at $($Dst.role) but ACK lost on return -> $($Src.role) NAT restrictive/symmetric. Check $($Src.role)'s live/log for 'unsolicited' (=timing, re-test) vs silence (=real loss).") -ForegroundColor Yellow
    } else {
      Write-Host ($line + "REQ never reached $($Dst.role) -> $($Dst.role) NAT/firewall drops inbound UDP (or wrong ip/port).") -ForegroundColor Red
    }
  }
  Show-Direction -Src $a -Dst $b
  Show-Direction -Src $b -Dst $a
  Write-Host ""
  return
}

# ─────────────────────────────────────────────────────────────────────────────
# RUN MODE — baseline -> synchronized cross-fire rounds -> deltas.
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== GATE R.0 hole-punch field test — node $Role ===" -ForegroundColor Cyan
Write-Host "local=$Local  peer=$PeerIp`:$PeerUdpPort  rounds=$Rounds  interval=${IntervalSec}s"

$base = Get-HpStatus -Base $Local
if (-not $base['utp_hole_punch_enabled']) {
  Write-Warning "utp_hole_punch_enabled is FALSE — enable hole-punch in Preferences or every fire returns 'holepunch_disabled'."
}
if (-not $base['kad_connected']) {
  Write-Warning "kad_connected is FALSE — Kad must be connected for the punch to route. Connect Kad first."
}

# Resolve the synchronized round-0 instant.
$now = Get-Date
if ([string]::IsNullOrWhiteSpace($FireAt)) {
  $t0 = $now
  Write-Host "FireAt not set -> firing immediately (manual countdown on both nodes)." -ForegroundColor DarkYellow
} else {
  $t0 = [DateTime]::Today.Add([TimeSpan]::Parse($FireAt))
  if ($t0 -lt $now) {
    Write-Warning "FireAt $FireAt already passed today -> firing immediately."
    $t0 = $now
  } else {
    Write-Host ("Waiting until $($t0.ToString('HH:mm:ss')) for synchronized round 0...") -ForegroundColor DarkCyan
  }
}

$totals = @{}; foreach ($k in $CounterKeys) { $totals[$k] = [int64]0 }
$rows = @()

for ($r = 0; $r -lt $Rounds; $r++) {
  $target = $t0.AddSeconds($r * $IntervalSec)
  $wait = ($target - (Get-Date)).TotalSeconds
  if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }

  $before = Get-HpStatus -Base $Local
  $fired = Invoke-HpFire -Base $Local -Ip $PeerIp -Port $PeerUdpPort
  Start-Sleep -Seconds $SettleSec
  $after = Get-HpStatus -Base $Local
  $d = Get-Delta -Before $before -After $after
  foreach ($k in $CounterKeys) { $totals[$k] += $d[$k] }

  $fireErr = ""
  if ($null -ne $fired -and $fired.PSObject.Properties.Name -contains 'error' -and $fired.error -ne 'ok') { $fireErr = " [$($fired.error)]" }

  $stamp = (Get-Date).ToString('HH:mm:ss')
  Write-Host ("[r{0} {1}] dattempts={2} dsuccess={3} dreq_recv={4} dchallenge={5} dsymnat={6}{7}" -f `
    $r, $stamp, $d['hole_punch_attempts'], $d['hole_punch_success'], $d['hole_punch_req_recv'], `
    $d['hole_punch_challenge_sent'], $d['hole_punch_sym_nat_fail'], $fireErr)

  $rows += [PSCustomObject]@{ round = $r; time = $stamp; delta = $d; fire = $fired }
}

Write-Host ""
Write-Host "── totals (this node) ─────────────────────────────" -ForegroundColor Cyan
foreach ($k in $CounterKeys) {
  Write-Host ("  {0,-26} +{1}" -f $k, $totals[$k])
}
Write-Host ""
$paste = Format-PasteBack -RoleLabel $Role -Rnds $Rounds -Tot $totals
Write-Host $paste -ForegroundColor Green
Write-Host ""
Write-Host "Paste this node's line together with the other node's line to fill the A<->B matrix." -ForegroundColor DarkGray

if (-not [string]::IsNullOrWhiteSpace($OutFile)) {
  $summary = [PSCustomObject]@{
    role        = $Role
    local       = $Local
    peer_ip     = $PeerIp
    peer_udp    = $PeerUdpPort
    rounds      = $Rounds
    fired_at    = $t0.ToString('o')
    baseline    = $base
    final_totals_note = "totals = sum of per-round deltas"
    totals      = $totals
    rows        = $rows
  }
  $summary | ConvertTo-Json -Depth 8 | Out-File -FilePath $OutFile -Encoding utf8
  Write-Host "wrote $OutFile" -ForegroundColor DarkGray
}
