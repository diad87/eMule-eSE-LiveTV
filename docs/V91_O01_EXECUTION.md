# V91-O01 physical dual-stack execution

## Current result

`V91-O01` is **PASS**. The uninterrupted 43,200-second formal window completed
on both physical Windows nodes and the aggregate finalizer returned PASS.

- Formal run: `9108ff953fb044ef91f4d6c3cab521cc`
- Formal H1 job: `3e20f7c8386a43f082fb2a21e688f743`
- Formal H3 job: `de2efd17caf34b29bc1aae33f35b5cae`
- Preflight run: `7d50220997e24f3b9ee5ba88883e306b`
- Candidate `emule.exe` SHA-256:
  `0bc2ca4e0d161fc90c1f42009bc1c2e793f6dc1c13c973bebb935d65aff839bd`
- H1 and H3 jobs: COMPLETE, exit code 0
- Aggregate: `ese.v91.o01-aggregate/v1`, `PASS`
- Requested measured duration: 43,200 seconds after LiveTV warm-up
- H1: 43,213.924 wall seconds and 2,816 samples
- H3: 43,305.373 wall seconds and 2,849 samples

The formal viewer advanced from 62 to 44,631 chunks. Its incremental duplicate
ratio was 3.24% and cumulative-ratio drift was 3.24 points, below the 25% and
5-point limits. Final-minus-initial working-set growth was negative on both
nodes; handle growth was +4 on H1 and -5 on H3. Both nodes observed the
physical IPv6 LiveTV peer, the physical IPv4 file peer, a valid playlist and
valid segments. The canonical 4 GiB SHA-256 and ED2K matched at both ends.

## Physical preflight evidence

Two physical Windows hosts used one candidate process each. The same process
simultaneously maintained:

- 12 Mbps LiveTV over the controlled physical IPv6 path;
- the canonical 4 GiB eMule transfer over physical IPv4;
- a responsive local API and valid HLS playlist/segments.

Both processes observed the IPv6 Live peer and the IPv4 file peer. The
destination independently reproduced the canonical SHA-256 and ED2K:

- SHA-256:
  `1016d6f63ae1649a879a7c0de30865ed132deb37b1c3b2bc9ca004c88feee26c`
- ED2K: `796A95E75DF8E78D54A57CDEA1FEDE84`

The viewer advanced from 61 to 634 chunks. Its incremental duplicate ratio was
3.84% and cumulative-ratio drift was 3.47 points, below the 25% and 5-point
limits. Final-minus-initial working-set growth was negative on both nodes;
handle growth was +6 on H1 and -3 on H3.

## Formal runner

The unattended runner:

- discovers the current physical IPv4 address of each NIC instead of assuming
  a DHCP lease;
- creates the controlled ULA route and fixes a dual-stack `[::]` listener;
- warms LiveTV before fixing the resource and duplicate-counter baselines;
- starts the IPv4 transfer inside the measured window;
- samples process, API and LiveTV every 15 seconds;
- records first and last IPv4/IPv6 5-tuples, effective routes and physical
  `InterfaceGuid`;
- rejects non-monotonic counters, gaps over 30 seconds, incomplete time span,
  bad hashes, excessive growth or ratio drift;
- emits `PREFLIGHT_PASS` below 43,200 seconds and can emit formal `PASS` only
  after the complete normative duration.

## Evidence

- `../lab-runs/v91-k04/7d50220997e24f3b9ee5ba88883e306b/manifest.json`
- `../lab-runs/v91-k04/7d50220997e24f3b9ee5ba88883e306b/h1-result.json`
- `../lab-runs/v91-k04/7d50220997e24f3b9ee5ba88883e306b/h3-result.json`
- `../lab-runs/v91-k04/7d50220997e24f3b9ee5ba88883e306b/aggregate-result.json`
- `../lab-runs/v91-k04/9108ff953fb044ef91f4d6c3cab521cc/manifest.json`
- `../lab-runs/v91-k04/9108ff953fb044ef91f4d6c3cab521cc/h1-result.json`
- `../lab-runs/v91-k04/9108ff953fb044ef91f4d6c3cab521cc/h3-result.json`
- `../lab-runs/v91-k04/9108ff953fb044ef91f4d6c3cab521cc/aggregate-result.json`
- `V91_O01_RESULT.json`

## Campaign impact

The cumulative matrix is **22 PASS, 0 FAIL and 5 BLOCKED** (81.5% PASS).
