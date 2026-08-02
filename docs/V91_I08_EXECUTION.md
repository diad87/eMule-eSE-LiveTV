# V91-I08 exact-candidate execution

## Result

`V91-I08` is **PASS**.

- Run: `6cc46ecc95b9465e9eeac5a2a9773539`
- Candidate `emule.exe` SHA-256:
  `8b0e2f554d369a7cae7c53e7d118f8d88bddd729b5981ae7e974aedcd295c506`
- Candidate size: 11,279,360 bytes
- H1 job: `b76f0377a07d43da9e82019933b2a289`, COMPLETE, exit code 0
- H3 job: `9d857eb0533c48cf9b788fcf760592e4`, COMPLETE, exit code 0
- Aggregate finalizer: PASS at `2026-07-31T07:39:26.1178231+00:00`

## What was proved

The production eMule executable, not the test runner, opened one TCP and one
UDP socket to the independent Windows echo fixture over the controlled T5 IPv6
path. Both transports carried and returned the same 79-byte payload bound to
nonce `6074a0a0cdc04e779bc0ec31369d7df5`.

The independent fixture observed:

- Destination: exact H1 IPv6 and 128-bit bytes observed, values redacted.
- Source: exact H3 IPv6 observed on both TCP and UDP, value redacted.
- TCP port: 48808; UDP port: 48809
- Payload SHA-256 on both transports:
  `03d88d2dbfeb463ba3fdb9277619a13120e0316d61138d8b5a370cdcd9d11e62`

The client reported `success=true`, 79 bytes returned on each transport and
zero TCP/UDP errors. The adjudicator compared parsed 16-byte addresses, not
textual IPv6 formatting, so compressed and expanded spellings cannot create a
false result.

## Safety and verification

The client action is local/admin-only through the existing Web API boundary,
requires active NetLab contribution consent, accepts only a literal native
IPv6 address, rejects mapped IPv4, restricts ports and timeouts, rate-limits
requests and performs no DNS lookup.

- eSE Live regression suite: 39/39 PASS.
- PowerShell 5.1 parser: zero errors in runner and controller.
- Release x64 project build: zero errors.
- H3 candidate receipt: matching SHA-256 and byte length, PASS.
- Formal two-node executor: COMPLETE/0 on H1 and H3.
- Cross-node aggregate adjudication: PASS.

## Evidence

- `../lab-runs/v91-k04/6cc46ecc95b9465e9eeac5a2a9773539/manifest.json`
- `../lab-runs/v91-k04/6cc46ecc95b9465e9eeac5a2a9773539/h1-result.json`
- `../lab-runs/v91-k04/6cc46ecc95b9465e9eeac5a2a9773539/h3-result.json`
- `../lab-runs/v91-k04/6cc46ecc95b9465e9eeac5a2a9773539/aggregate-result.json`
- `../lab-runs/v91-k04/candidate-receipt-8b0e2f55.json`

## Campaign impact

The cumulative v9.1 matrix is now **20 PASS, 0 FAIL and 7 BLOCKED**
(74.1% PASS). The normative release gate remains NO_GO while mandatory cases
remain BLOCKED.
