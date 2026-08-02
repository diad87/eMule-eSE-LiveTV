# V91-K01 exact-candidate execution

## Result

`V91-K01` is **PASS**.

- Run: `1a9c4ddc09f147889a28e5e110865cdb`
- Candidate `emule.exe` SHA-256:
  `fdce4011f28a7792b1e80d749f5a07f9f35dbf50e9f4b558a760134e9edbd4e9`
- Candidate size: 11,274,240 bytes
- H1 job: `31b67e9112eb4285ad3d3d24ec2640dd`, COMPLETE, exit code 0
- H3 job: `0278fc50c87a4fc990a1ebd4692a35dc`, COMPLETE, exit code 0
- Aggregate finalizer: PASS at `2026-07-31T07:20:59.2459839+00:00`

## What was proved

The controlled T5 fixture ran Kad6 only (`kad_configured_mask=2`,
`kad_running_mask=2`, Kad2 off) on the source and requester. Both endpoints
formed authenticated two-hop circuits. The source-side pipeline changed from
zero to one advertised source, and the requester-side pipeline changed from
zero to one recovered source. Both node results and the cross-node aggregate
adjudicator passed against the same candidate hash.

The runtime ticket used the stable origin circuit identifier as its provenance
session, allowing the requester to validate and materialize the source returned
through the exit without weakening the production target policy.

## Verification

- eSE Live regression suite: 38/38 PASS.
- Kad6 ticket suite: 72/72 PASS.
- Release x64 solution build: 0 errors.
- H3 candidate receipt: matching SHA-256 and byte length, PASS.
- Formal two-node executor: COMPLETE/0 on H1 and H3.
- Aggregate adjudication: PASS.

## Evidence

- `../lab-runs/v91-k04/1a9c4ddc09f147889a28e5e110865cdb/manifest.json`
- `../lab-runs/v91-k04/1a9c4ddc09f147889a28e5e110865cdb/h1-result.json`
- `../lab-runs/v91-k04/1a9c4ddc09f147889a28e5e110865cdb/h3-result.json`
- `../lab-runs/v91-k04/1a9c4ddc09f147889a28e5e110865cdb/aggregate-result.json`
- `../lab-runs/v91-k04/candidate-receipt-fdce4011.json`

## Campaign impact

The cumulative v9.1 matrix is now **19 PASS, 0 FAIL and 8 BLOCKED**
(70.4% PASS). The normative release gate remains NO_GO while mandatory cases
remain BLOCKED.
